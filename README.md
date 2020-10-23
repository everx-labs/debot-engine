# DEngine

DEngine is a rust library that implements debot engine and allows to run debot smart contracts.

## How to build

    cargo build [--release]

## How to use

Add to your Cargo.toml:

```toml
[dependencies]
debot-engine = { git = 'https://github.com/tonlabs/debot-engine.git' }
```

## Example

Simple debot browser which uses DEngine can be found here `./tests/integration_test.rs`

DEngine is used by [tonos-cli](https://github.com/tonlabs/tonos-cli).
Run debots in tonos-cli with the following command:

    tonos-cli debot fetch <debot_address>

## Related Links

- [TON OS docs](https://docs.ton.dev/)

- [DeBot smart contract examples](https://github.com/tonlabs/ton-labs-contracts/tree/master/solidity/debots)

