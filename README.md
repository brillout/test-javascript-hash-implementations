The goal is to find a JavaScript hash implementation that is both light and fast.
The JavaScript is considered to be run in the browser.
The hash implementations are tested on speed by hashing the source code of JavaScript libraries.


Tested are implementations for following Hash Functions
  - SHA-256
  - SHA-3
  - CRC32
  - blake2s


Of all tested SHA-256 implementations, <a href='http://brillout.github.io/test-javascript-hash-implementations/computed_c720.html'>results with an Intel Celeron 2955U @ 1.4GHz</a> suggests that <a href='https://github.com/digitalbazaar/forge'>forge</a> is the fastest SHA-256 JavaScript implementation.
Even though the original source code weights 284 KB, extracting the code related to SHA-256 reduces the size to 4.5 KB, see https://github.com/brillout/forge-sha256.


### Run the tests

Go to http://brillout.github.io/test-javascript-hash-implementations/ and wait a bit.
