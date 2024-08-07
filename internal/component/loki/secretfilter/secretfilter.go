package secretfilter

import (
	"context"
	"embed"
	"regexp"
	"strings"
	"sync"

	"github.com/BurntSushi/toml"
	"github.com/grafana/alloy/internal/component"
	"github.com/grafana/alloy/internal/component/common/loki"
	"github.com/grafana/alloy/internal/featuregate"
	"github.com/grafana/alloy/internal/runtime/logging/level"
)

//go:embed gitleaks.toml
var embedFs embed.FS

type Rule struct {
	name  string
	regex *regexp.Regexp
}

func init() {
	component.Register(component.Registration{
		Name:      "loki.secretfilter",
		Stability: featuregate.StabilityGenerallyAvailable, // To make it easy to test for now. Change to featuregate.StabilityExperimental
		Args:      Arguments{},
		Exports:   Exports{},

		Build: func(opts component.Options, args component.Arguments) (component.Component, error) {
			return New(opts, args.(Arguments))
		},
	})
}

// Arguments holds values which are used to configure the secretfilter
// component.
type Arguments struct {
	ForwardTo      []loki.LogsReceiver `alloy:"forward_to,attr"`
	GitleaksConfig string              `alloy:"gitleaks_config,attr,optional"`
	Types          []string            `alloy:"types,attr,optional"`
	RedactWith     string              `alloy:"redact_with,attr,optional"`
	ExcludeGeneric bool                `alloy:"exclude_generic,attr,optional"`
}

// Exports holds the values exported by the secretfilter component.
type Exports struct {
	Receiver loki.LogsReceiver `alloy:"receiver,attr"`
}

// DefaultArguments defines the default settings for log scraping.
var DefaultArguments = Arguments{}

// SetToDefault implements syntax.Defaulter.
func (args *Arguments) SetToDefault() {
	*args = DefaultArguments
}

var (
	_ component.Component = (*Component)(nil)
)

// Component implements the loki.source.file component.
type Component struct {
	opts component.Options

	mut      sync.RWMutex
	args     Arguments
	receiver loki.LogsReceiver
	fanout   []loki.LogsReceiver
	Rules    []Rule
}

// Not exhaustive. See https://github.com/gitleaks/gitleaks/blob/master/config/config.go
type GitLeaksConfig struct {
	AllowList struct {
		Description string
		Paths       []string
	}
	Rules []struct {
		ID          string
		Description string
		Regex       string
		Keywords    []string

		Allowlist struct {
			StopWords []string
		}
	}
}

// New creates a new secretfilter component.
func New(o component.Options, args Arguments) (*Component, error) {
	c := &Component{
		opts:     o,
		receiver: loki.NewLogsReceiver(),
	}

	// Parse GitLeaks configuration
	var gitleaksCfg GitLeaksConfig
	if args.GitleaksConfig == "" {
		// If no config file provided, use the embedded one
		_, err := toml.DecodeFS(embedFs, "gitleaks.toml", &gitleaksCfg)
		if err != nil {
			return nil, err
		}
	} else {
		// If a config file is provided, use that
		_, err := toml.DecodeFile(args.GitleaksConfig, &gitleaksCfg)
		if err != nil {
			return nil, err
		}
	}

	// Compile regexes
	for _, rule := range gitleaksCfg.Rules {
		// If the users wants to exclude the generic API key rule, skip it
		if args.ExcludeGeneric && strings.ToLower(rule.ID) == "generic-api-key" {
			continue
		}
		// If specific secret types are provided, only include rules that match the types
		if args.Types != nil && len(args.Types) > 0 {
			var found bool
			for _, t := range args.Types {
				if strings.HasPrefix(strings.ToLower(rule.ID), strings.ToLower(t)) {
					found = true
					continue
				}
			}
			if !found {
				// Skip that rule if it doesn't match any of the secret types
				continue
			}
		}
		re, err := regexp.Compile(rule.Regex)
		if err != nil {
			return nil, err
		}
		c.Rules = append(c.Rules, Rule{
			name:  rule.ID,
			regex: re,
		})
	}
	level.Info(c.opts.Logger).Log("Compiled regexes for secret detection", len(c.Rules))

	// Call to Update() once at the start.
	if err := c.Update(args); err != nil {
		return nil, err
	}

	// Immediately export the receiver which remains the same for the component
	// lifetime.
	o.OnStateChange(Exports{Receiver: c.receiver})

	return c, nil
}

// Run implements component.Component.
func (c *Component) Run(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case entry := <-c.receiver.Chan():
			for _, r := range c.Rules {
				var redactWith = "<REDACTED-SECRET:" + r.name + ">"
				if c.args.RedactWith != "" {
					redactWith = strings.ReplaceAll(c.args.RedactWith, "$SECRET_NAME", r.name)
				}

				// There seems to be two kinds of regexes in the gitleaks.toml file
				// 1. Regexes that only match the secret (with no submatches). E.g. (?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}
				// 2. Regexes that match the secret and some context (or delimiters) and have one submatch (the secret itself). E.g. (?i)\b(AIza[0-9A-Za-z\\-_]{35})(?:['|\"|\n|\r|\s|\x60|;]|$)
				//
				// For the first case, we can replace the entire match with the redaction string.
				// For the second case, we can replace the first submatch with the redaction string (to avoid redacting delimiters).
				for _, occ := range r.regex.FindAllStringSubmatch(entry.Line, -1) {
					if len(occ) == 2 {
						entry.Line = strings.ReplaceAll(entry.Line, occ[1], redactWith)
					} else {
						entry.Line = strings.ReplaceAll(entry.Line, occ[0], redactWith)
					}
				}
			}

			for _, f := range c.fanout {
				select {
				case <-ctx.Done():
					return nil
				case f.Chan() <- entry:
				}
			}
		}
	}
}

// Update implements component.Component.
func (c *Component) Update(args component.Arguments) error {
	newArgs := args.(Arguments)

	c.mut.Lock()
	defer c.mut.Unlock()
	c.args = newArgs

	c.fanout = newArgs.ForwardTo

	return nil
}
