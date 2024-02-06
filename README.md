# Bee BTCEC v1 vs v2

This repository validates byte compatibility between

- github.com/btcsuite/btcd v0.22.3
- github.com/btcsuite/btcd/btcec/v2 v2.3.2

that are used in the crypto functions in github.com/ethersphere/bee
by the initial changes in <https://github.com/ethersphere/bee/pull/4516>.

```sh
go test -v -count 1 .
```

It validates cross-compatibility between functions:

- `crypto.EncodeSecp256k1PrivateKey` and `crypto.DecodeSecp256k1PrivateKey`
- `crypto.Signer.Sign` and `crypto.Recover`
- `pss.Wrap` and `pss.Unwrap`

With private keys generated with both v1 and v2 `btcec.S256()` curve function.
