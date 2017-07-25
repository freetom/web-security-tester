fs = require('fs')
fs.readFile('/home/bortoli/Downloads/web-trace.json', 'utf8', function (err,data) {
  if (err) {
    return console.log(err)
  }
  trace = JSON.parse(data)
  console.log(trace)
});
