The goal is to find a secure hash JavaScript implementation that is both compact and fast.
The JavaScript is considered to be run in the browser.

The <a href='http://brillout.github.io/test-secure-hash-algos/computed_c720.html'>results on a Chromebook C720</a> suggests that <a href='https://github.com/digitalbazaar/forge'>forge</a> is by far the fastest SHA-256 JavaScript implementation.
Even though it is 284KB, extracting SHA-256 from it could reduce the required size. According issue: <a href='https://github.com/brillout/test-secure-hash-algos/issues/1'>issue</a>.

This repository is a quick test to grasp what hashing algorithms are out there and how well they perform.
It is not exhaustive.
E.g. other than `blake2s` all hashing algorithms are `SHA-256` implementations and it would be nice to test other cryptographic hashes.
Feel Free to open Issues / PRs.

### Run the tests

Go to <a href='http://brillout.github.io/test-secure-hash-algos/'>http://brillout.github.io/test-secure-hash-algos/</a> and wait a bit.

If a fast and compact SHA-256 is missing from the list, please open an Issue or PR.
