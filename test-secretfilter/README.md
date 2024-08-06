Start the docker-compose stack with the following command:
```bash
make up
```

Then you can check the logs on the following page: 
http://localhost:3000/explore?schemaVersion=1&panes=%7B%221gy%22%3A%7B%22datasource%22%3A%22P8E80F9AEF21F6940%22%2C%22queries%22%3A%5B%7B%22refId%22%3A%22A%22%2C%22expr%22%3A%22%7Bfilename%3D%5C%22%2Ftmp%2Falloy%2Fdummy.log%5C%22%7D+%7C%3D+%60%60%22%2C%22queryType%22%3A%22range%22%2C%22datasource%22%3A%7B%22type%22%3A%22loki%22%2C%22uid%22%3A%22P8E80F9AEF21F6940%22%7D%2C%22editorMode%22%3A%22builder%22%7D%5D%2C%22range%22%3A%7B%22from%22%3A%22now-1h%22%2C%22to%22%3A%22now%22%7D%7D%7D&orgId=1