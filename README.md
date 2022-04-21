# secp256k1 key did provider
This is a DID Provider which implements [EIP2844](https://eips.ethereum.org/EIPS/eip-2844) for `did:key:` using secp256k1. It does not support encryption / JWE. It is based on [key-did-provider-ed25519](https://github.com/ceramicnetwork/key-did-provider-ed25519) and was designed to be used with [Ceramic](https://ceramic.network/).

## Installation

```
npm install --save key-did-provider-secp256k1
```

## Usage

```js
import { Secp256k1Provider } from 'key-did-provider-ed25519'
import KeyResolver from 'key-did-resolver'
import { DID } from 'dids'

const seed = new Uint8Array(...) //  32 bytes with high entropy
const provider = new Secp256k1Provider(seed)
const did = new DID({ provider, resolver: KeyResolver.getResolver() })
await did.authenticate()

// log the DID
console.log(did.id)

// create JWS
const { jws, linkedBlock } = await did.createDagJWS({ hello: 'world' })

// verify JWS
await did.verifyJWS(jws)

```

## License

Apache-2.0 OR MIT