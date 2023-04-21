import moment from 'moment'
import { StatusList } from '../src'
import { privateKeyJwk, signer, verifier } from './utils'

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
      validFrom: '2021-04-05T14:27:40.000Z',
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
      validFrom: '2021-04-05T14:27:40.000Z',
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
