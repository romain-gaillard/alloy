package pigiron

import (
	"context"
	"path/filepath"
	"sync"
	"time"

	"github.com/grafana/alloy/internal/component"
	"github.com/grafana/alloy/internal/component/common/loki"
	"github.com/grafana/alloy/internal/featuregate"
	"github.com/grafana/alloy/internal/runtime/logging/level"

	"strconv"

	"github.com/nlpodyssey/cybertron/pkg/models/bert"
	"github.com/nlpodyssey/cybertron/pkg/tasks/tokenclassification"
	"github.com/nlpodyssey/cybertron/pkg/tokenizers"
	"github.com/nlpodyssey/cybertron/pkg/tokenizers/bpetokenizer"
	"github.com/nlpodyssey/cybertron/pkg/vocabulary"
	voc2 "github.com/nlpodyssey/gotokenizers/vocabulary"
	"github.com/nlpodyssey/spago/mat"
	"github.com/nlpodyssey/spago/nn"
)

func init() {
	component.Register(component.Registration{
		Name:      "loki.pigiron",
		Stability: featuregate.StabilityExperimental,
		Args:      Arguments{},
		Exports:   Exports{},

		Build: func(opts component.Options, args component.Arguments) (component.Component, error) {
			return New(opts, args.(Arguments))
		},
	})
}

// Arguments holds values which are used to configure the loki.pigiron
// component.
type Arguments struct {
	ForwardTo []loki.LogsReceiver `alloy:"forward_to,attr"`
	ModelPath string              `alloy:"model_path,attr"`
}

// Exports holds the values exported by the loki.pigiron component.
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

// Component implements the loki.pigiron component.
type Component struct {
	opts component.Options

	mut      sync.RWMutex
	args     Arguments
	receiver loki.LogsReceiver
	fanout   []loki.LogsReceiver
	mlLabels []string
	model    *bert.ModelForTokenClassification
	bpe      *bpetokenizer.BPETokenizer
}

func (c *Component) ID2Label(value map[string]string) []string {
	y := make([]string, len(value))
	for k, v := range value {
		i, err := strconv.Atoi(k)
		if err != nil {
			level.Error(c.opts.Logger).Log("msg", "error converting ID to int", "error", err)
		}
		y[i] = v
	}
	return y
}

func (c *Component) getBestClass(logits mat.Tensor, Labels []string) (string, float64) {
	probs := logits.Value().(mat.Matrix).Softmax()
	argmax := probs.ArgMax()
	return Labels[argmax], probs.At(argmax).Item().F64()
}

func (c *Component) convertVocab(vocab *voc2.Vocabulary) *vocabulary.Vocabulary {
	vocabList := make([]string, vocab.Size())
	for i := 0; i < vocab.Size(); i++ {
		str, ok := vocab.GetString(i)
		if ok {
			vocabList[i] = str
		}
	}
	return vocabulary.New(vocabList)
}

// New creates a new loki.pigiron component.
func New(o component.Options, args Arguments) (*Component, error) {
	c := &Component{
		opts:     o,
		receiver: loki.NewLogsReceiver(),
	}

	level.Info(c.opts.Logger).Log("msg", "loading model", "model_path", args.ModelPath)

	bpe, err := bpetokenizer.NewFromModelFolder(args.ModelPath)
	if err != nil {
		level.Error(c.opts.Logger).Log("msg", "error loading BPE tokenizer", "error", err)
		return nil, err
	}
	c.bpe = bpe

	config, err := bert.ConfigFromFile[bert.Config](filepath.Join(args.ModelPath, "config.json"))
	if err != nil {
		level.Error(c.opts.Logger).Log("msg", "error loading model config", "error", err)
		return nil, err
	}
	c.mlLabels = c.ID2Label(config.ID2Label)

	model, err := nn.LoadFromFile[*bert.ModelForTokenClassification](filepath.Join(args.ModelPath, "spago_model.bin"))
	if err != nil {
		level.Error(c.opts.Logger).Log("msg", "error loading model", "error", err)
		return nil, err
	}

	// Overwrite vocabulary from model file with vocabulary from JSON file
	newVocab, err := voc2.FromJSONFile(filepath.Join(args.ModelPath, "vocab.json"))
	if err != nil {
		level.Error(c.opts.Logger).Log("msg", "error loading vocabulary", "error", err)
		return nil, err
	}
	model.Bert.Embeddings.Vocab = c.convertVocab(newVocab)
	c.model = model

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
			text := entry.Line
			start := time.Now()

			tokenized, err := c.bpe.Tokenize(text)
			if err != nil {
				level.Error(c.opts.Logger).Log("msg", "error tokenizing text", "error", err)
			}

			logits := c.model.Classify(tokenizers.GetStrings(tokenized))
			tokens := make([]tokenclassification.Token, 0, len(tokenized))
			for i, token := range tokenized {
				label, score := c.getBestClass(logits[i], c.mlLabels)
				start := token.Offsets.Start
				end := token.Offsets.End
				tokens = append(tokens, tokenclassification.Token{
					Text:  text[start:end],
					Start: start,
					End:   end,
					Label: label,
					Score: score,
				})
			}
			tokens = tokenclassification.FilterNotEntities(tokenclassification.Aggregate(tokens))

			level.Debug(c.opts.Logger).Log("msg", "entities", tokens)

			outputText := text
			diff := 0
			for _, token := range tokens {
				replacement := "<ALLOY-AI-REDACTED-SECRET:" + token.Label + ">"
				outputText = outputText[:token.Start+diff] + replacement + outputText[token.End+diff:]
				diff += len(replacement) - token.End + token.Start
			}

			entry.Line = outputText
			level.Info(c.opts.Logger).Log("msg", "time taken for model to process", "seconds", time.Since(start).Seconds())

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
