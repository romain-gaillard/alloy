Start the docker-compose stack with the following command:
```bash
make up
```

Then you can check the logs on the following page: 

For Regexes:
http://localhost:3000/explore?schemaVersion=1&panes=%7B%221gy%22:%7B%22datasource%22:%22P8E80F9AEF21F6940%22,%22queries%22:%5B%7B%22refId%22:%22A%22,%22expr%22:%22%7Bfilename%3D%5C%22%2Ftmp%2Falloy%2Flogs%2Fdummy.log%5C%22%7D%20%7C%3D%20%60%60%22,%22queryType%22:%22range%22,%22datasource%22:%7B%22type%22:%22loki%22,%22uid%22:%22P8E80F9AEF21F6940%22%7D,%22editorMode%22:%22builder%22%7D%5D,%22range%22:%7B%22from%22:%22now-1h%22,%22to%22:%22now%22%7D%7D%7D&orgId=1

http://localhost:3000/explore?schemaVersion=1&panes=%7B%221gy%22:%7B%22datasource%22:%22P8E80F9AEF21F6940%22,%22queries%22:%5B%7B%22refId%22:%22A%22,%22expr%22:%22%7Bfilename%3D%5C%22%2Ftmp%2Falloy%2Flogs%2Fdummy.json.log%5C%22%7D%20%7C%3D%20%60%60%22,%22queryType%22:%22range%22,%22datasource%22:%7B%22type%22:%22loki%22,%22uid%22:%22P8E80F9AEF21F6940%22%7D,%22editorMode%22:%22builder%22%7D%5D,%22range%22:%7B%22from%22:%22now-24h%22,%22to%22:%22now%22%7D%7D%7D&orgId=1


For AI: 
http://localhost:3000/explore?schemaVersion=1&panes=%7B%22xfh%22:%7B%22datasource%22:%22P8E80F9AEF21F6940%22,%22queries%22:%5B%7B%22refId%22:%22A%22,%22expr%22:%22%7Bfilename%3D%5C%22%2Ftmp%2Falloy%2Flogs-ai%2Fdummy.log%5C%22%7D%20%7C%3D%20%60%60%22,%22queryType%22:%22range%22,%22datasource%22:%7B%22type%22:%22loki%22,%22uid%22:%22P8E80F9AEF21F6940%22%7D,%22editorMode%22:%22builder%22%7D%5D,%22range%22:%7B%22from%22:%22now-1h%22,%22to%22:%22now%22%7D%7D%7D&orgId=1

The configuration of the Secret scanning component can be changed in `test-secretfilter/config.alloy`