import * as jose from 'jose'
import moment from 'moment'
import {
  StatusList,
  StatusListSignParameters,
  StatusListVerifyParameters,
  VerifiedJwt,
} from '../src'

const privateKeyJwk = {
  kty: 'EC',
  crv: 'P-256',
  alg: `ES256`,
  d: 'sjKZ6OT5F3d2IOiq9JkZ7WMR2rUqlNa3TumkrcedrBM',
  x: 'MYvnaI87pfrn3FpTqW-yNiFcF1K7fedJiqapm20_q7c',
  y: '9YEbT6Tyuc7xp9yRvhOUVKK_NIHkn5HpK9ZMgvK5pVw',
}

const signer = {
  sign: async ({ header, payload }: StatusListSignParameters) => {
    const jwt = await new jose.CompactSign(Buffer.from(JSON.stringify(payload)))
      .setProtectedHeader(header)
      .sign(await jose.importJWK(privateKeyJwk))
    return jwt
  },
}

const verifier = {
  verify: async ({ jwt }: StatusListVerifyParameters) => {
    // const { iss, kid } = jose.decodeProtectedHeader(jwt)
    // const publicKey = await getPublicKey(iss + kid);
    // or...
    const publicKey = await jose.importJWK(privateKeyJwk)
    const { payload, protectedHeader } = await jose.jwtVerify(jwt, publicKey)
    return { protectedHeader, payload } as VerifiedJwt
  },
}

it('create', async () => {
  const statusList = await StatusList.create({
    id: 'https://vendor.example/credentials/status/3',
    alg: privateKeyJwk.alg,
    iss: 'did:example:123',
    kid: '#0',
    iat: moment('2021-04-05T14:27:40Z').unix(),
    length: 8,
    purpose: 'suspension',
    signer,
  })
  const verified = await StatusList.verify({
    jwt: statusList,
    verifier,
  })
  expect(verified).toEqual({
    protectedHeader: {
      alg: 'ES256',
      iss: 'did:example:123',
      kid: '#0',
      typ: 'vc+ld+jwt',
      cty: 'vc+ld+json',
    },
    payload: {
      '@context': [
        'https://www.w3.org/2018/credentials/v1',
        'https://w3id.org/vc/status-list/2021/v1',
      ],
      id: 'https://vendor.example/credentials/status/3',
      type: ['VerifiableCredential', 'StatusList2021Credential'],
      issuer: 'did:example:123',
      issued: '2021-04-05T14:27:40.000Z',
      credentialSubject: {
        id: 'https://vendor.example/credentials/status/3#list',
        type: 'StatusList2021',
        statusPurpose: 'suspension',
        encodedList: 'H4sIAAAAAAAAA2MAAI3vAtIBAAAA',
      },
    },
  })
})

it('updateStatus', async () => {
  const statusList = await StatusList.create({
    id: 'https://vendor.example/credentials/status/3',
    alg: privateKeyJwk.alg,
    iss: 'did:example:123',
    kid: '#0',
    iat: moment('2021-04-05T14:27:40Z').unix(),
    length: 8,
    purpose: 'suspension',
    signer,
  })

  const updatedStatusList = await StatusList.updateStatus({
    jwt: statusList,
    position: 1,
    purpose: 'suspension',
    status: true,
    signer,
  })
  const verified = await StatusList.verify({
    jwt: updatedStatusList,
    verifier,
  })
  expect(verified).toEqual({
    protectedHeader: {
      alg: 'ES256',
      iss: 'did:example:123',
      kid: '#0',
      typ: 'vc+ld+jwt',
      cty: 'vc+ld+json',
    },
    payload: {
      '@context': [
        'https://www.w3.org/2018/credentials/v1',
        'https://w3id.org/vc/status-list/2021/v1',
      ],
      id: 'https://vendor.example/credentials/status/3',
      type: ['VerifiableCredential', 'StatusList2021Credential'],
      issuer: 'did:example:123',
      issued: '2021-04-05T14:27:40.000Z',
      credentialSubject: {
        id: 'https://vendor.example/credentials/status/3#list',
        type: 'StatusList2021',
        statusPurpose: 'suspension',
        encodedList: 'H4sIAAAAAAAAA3MAAB2u3qQBAAAA',
      },
    },
  })
})

it('checkStatus', async () => {
  const statusList = await StatusList.create({
    id: 'https://vendor.example/credentials/status/3',
    alg: privateKeyJwk.alg,
    iss: 'did:example:123',
    kid: '#0',
    iat: moment('2021-04-05T14:27:40Z').unix(),
    length: 8,
    purpose: 'suspension',
    signer,
  })
  const updatedStatusList = await StatusList.updateStatus({
    jwt: statusList,
    position: 1,
    purpose: 'suspension',
    status: true,
    signer,
  })
  const suspended = await StatusList.checkStatus({
    id: 'https://vendor.example/credentials/status/3',
    purpose: 'suspension',
    position: 1,
    resolver: {
      resolve: async () => {
        return updatedStatusList
      },
    },
    verifier,
  })
  expect(suspended).toEqual(true)
})
