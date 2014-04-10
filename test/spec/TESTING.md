# Testing

Gryphon as a "spec" provides 2 methods: `header` and `authenticate`. Any
other methods provided are helper methods for that platform, and so they
should have platform-specific tests. However, regardless of language,
Gryphon and all ports *SHOULD* sign, produce, and consume the same
headers.

All the tests of the signing and authenticating have been provided in
these YAML files. If you're writing a port in another language, you can
use these YAML files to test that you've built a proper port.

## Test Formats

All the tests for `gryphon.header()` as in the `header.yml` file. There
is a `tests` array inside, each containing a hash of test properties.
You'd likely want to use `name` as part of the test suite name. The
`desc` should describe to a human what the test is for.

### Header

A `header` test will include `request`, `options`, and `expected`.

- `request`:
  - `url`: the full url. parse this depending on your chosen language
  - `method`: the HTTP method
  - `payload`: An optional string value, which if supplied, must be
    signed as the `payload`.
- `options`
  - `pk`: The public key
  - `sk`: The secret key
  - `ts`: The timestamp
  - `nonce`: The nonce

The `expected` value is what should be expected to return from
`gryphon.header()`. The value will either be a string, a `null` value
for invalid inputs.

Some example test code:

```js
var req = parse(test.request);
var header = gryphon.header(test.options);
assert.equal(header, test.expected);
```

### Authenticate
