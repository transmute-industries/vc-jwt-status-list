# vc status list

[![CI](https://github.com/transmute-industries/vc-jwt-status-list/actions/workflows/ci.yml/badge.svg)](https://github.com/transmute-industries/vc-jwt-status-list/actions/workflows/ci.yml)
![Branches](./badges/coverage-branches.svg)
![Functions](./badges/coverage-functions.svg)
![Lines](./badges/coverage-lines.svg)
![Statements](./badges/coverage-statements.svg)
![Jest coverage](./badges/coverage-jest%20coverage.svg)

<!-- [![NPM](https://nodei.co/npm/@transmute/vc-jwt-status-list.png?mini=true)](https://npmjs.org/package/@transmute/vc-jwt-status-list) -->

<img src="./transmute-banner.png" />

#### [Questions? Contact Transmute](https://transmute.typeform.com/to/RshfIw?typeform-source=vc-jwt-status-list)

## Usage

```bash
npm install '@transmute/vc-jwt-status-list'
```

```ts
import status from '@transmute/vc-jwt-status-list';
```

```js
const status = require('@transmute/vc-jwt-status-list');
```


### Creating a StatusList

```ts
import moment from 'moment'
import {StatusList, SignParameters} from '@transmute/vc-jwt-status-list'
export const signer = {
  sign: async ({ header, claimset }: SignParameters) => {
    const jwt = await new jose.CompactSign(
      Buffer.from(JSON.stringify(claimset)),
    )
      .setProtectedHeader(header)
      .sign(await jose.importJWK(privateKeyJwk))
    return jwt
  },
}
const statusList = await StatusList.create({
    id: 'https://vendor.example/credentials/status/3',
    alg: 'ES256',
    iss: 'did:example:123',
    kid: '#0',
    iat: moment('2021-04-05T14:27:40Z').unix(),
    length: 8,
    purpose: 'suspension',
    signer,
  })
```


### Creating a Verifiable Credential With Status

```ts
import moment from 'moment'
import {StatusList, SignParameters} from '@transmute/vc-jwt-status-list'
export const signer = {
  sign: async ({ header, claimset }: SignParameters) => {
    const jwt = await new jose.CompactSign(
      Buffer.from(JSON.stringify(claimset)),
    )
      .setProtectedHeader(header)
      .sign(await jose.importJWK(privateKeyJwk))
    return jwt
  },
}
const verifiableCredential = await VerifiableCredential.create({
    header: {
      alg: 'ES256',
      iss: 'did:example:123',
      kid: '#0',
      typ: 'vc+ld+jwt',
      cty: 'vc+ld+json',
    },
    claimset: {
      '@context': [
        'https://www.w3.org/ns/credentials/v2',
        'https://w3id.org/vc/status-list/2021/v1',
      ],
      id: 'http://example.com/credentials/1872',
      type: ['VerifiableCredential', 'NewCredentialType'],
      issuer: {
        id: 'did:example:123',
        type: ['Organization', 'OrganizationType'],
      },
      validFrom: '2010-01-01T19:23:24Z',
      credentialStatus: {
        id: 'https://example.com/credentials/status/3#4',
        type: 'StatusList2021Entry',
        statusPurpose: 'suspension',
        statusListIndex: '4',
        statusListCredential: 'https://example.com/credentials/status/3',
      },
      credentialSubject: {
        id: 'did:example:456',
        type: ['Person', 'JobType'],
        claimName: 'claimValue',
      },
    },
    signer,
  })
```

### Verifying & Suspending a Verifiable Credential With Status

```ts
const resolver = {
  resolve: async (id: string) => {
    if (id === 'https://example.com/credentials/status/3') {
      return statusList
    }
    throw new Error('unsupported status list.')
  },
}
const beforeSuspension = await VerifiableCredential.verify({
  jwt: verifiableCredential,
  verifier,
  resolver,
})
// beforeSuspension.suspension is false
const updatedStatusList = await VerifiableCredential.updateStatus({
  jwt: verifiableCredential,
  purpose: 'suspension',
  status: true,
  resolver,
  verifier,
  signer,
})
const afterSuspension = await VerifiableCredential.verify({
  jwt: verifiableCredential,
  verifier,
  resolver: {
    resolve: async (id: string) => {
      if (id === 'https://example.com/credentials/status/3') {
        return updatedStatusList
      }
      throw new Error('unsupported status list.')
    },
  },
})
// afterSuspension.suspension is true
```

## Develop

```bash
npm i
npm t
npm run lint
npm run build
```