# p2p-node-handshake
This is my solution for the [Eiger coding challenge](https://github.com/eqlabs/recruitment-exercises/blob/master/node-handshake.md).
It implements the initialization of a Bitcoin connection handshake.

## Advanced Rust features

The task at hand did not offer obvious ways to use macros or advanced lifetimes - I am familiar with them but refrained
from introducing them in artificial ways.

## Separation into generic and Bitcoin specific code

The separation of the code into `generic` and `bitcoin` is probably overkill relative to the requirements, but I got
carried away, and it makes for clean separation of concerns. Plus it allows for showcasing Rust features :-)

## Verifying the handshake with bitcoind

### tl;dr

To verify the handshake against a 'real' Bitcoin node, download the Bitcoin reference implementation and start 
`bitcoind` on the `regtest` chain:

```shell
.../bitcoin-22.0/bin/bitcoind -datadir=<path-of-your-choice>/bitcoin_data/ -chain=regtest -bind=127.0.0.1 -debug=net
```

Then run an integration test that is normally ignored in a different shell:

```shell
cargo test bitcoind -- --ignored --nocapture
```

Then look at both logs.

### In detail

Unit tests are good for ensuring robustness and finding regressions, but for a published API it is necessary to test
against other implementations. For the Bitcoin protocol, I chose the `bitcond` reference implementation.

If this was a 'real' project, it'd be good to automate this regression test, but that looked like overkill for this
coding challenge :-).

To prepare the test against bitcoind, perform the following steps (details are described for Linux, adjust for
other OSs):
* Download the latest version of the Bitcoin reference implementation from
   https://bitcoin.org/bin/bitcoin-core-22.0/bitcoin-22.0-x86_64-linux-gnu.tar.gz and extract to a folder of your
   choice.
* Create a folder for it to store its data: `mkdir -p <path-of-your-choice>/bitcoind-data`
* Run `bitcoind` in a shell, substituting the paths where bitcoind was extracted and the folder for bitcoin data. Details
   are important for the integration test to run:
  * `-chain=regtest` picks the regression test chain, which is hard-coded in the integration test implementation
  * `bind=127.0.0.1` is the address that's hard-coded in the integration test code
  * `-debug=net` enables logging, allowing us to verify that bitcoind completed the handshake on its side
```shell
.../bitcoin-22.0/bin/bitcoind -datadir=<path-of-your-choice>/bitcoin_data/ -chain=regtest -bind=127.0.0.1 -debug=net
```

That should have `bitcoind` up and running, and we can run the integration test against it. The integration test
can be run repeatedly against a single instance of `bitcoind`.

The test code is implemented as an `#[ignore]`'d integration test with hard-coded addresses, and can be run with `cargo`:

```shell
cargo test bitcoind -- --ignored --nocapture
```

Successful completion of the handshake can be seen in the log output. Locally, there should be messages like the
following:
```
DEBUG [p2p_node_handshake::handshake] client-side handshake completed - peer version data is NegotiatedVersion { ... }```
...
INFO  [integration_with_bitcoind] handshake with bitcoind successful
```

`bitcoind`'s log output should say that a `version` message was received, a `version` message was sent, a `verack` message
was sent, and a `verack` message was received. There is a message that `Connection reset by peer` which is expected
behavior - the integration test just drops the connection after handshake was completed.

## Resources

* Bitcoin network protocol: https://en.bitcoin.it/wiki/Protocol_documentation
* Bitcoin version handshake: https://en.bitcoin.it/wiki/Version_Handshake
