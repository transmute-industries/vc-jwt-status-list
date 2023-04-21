import fs from 'fs'
import moment from 'moment'
import { VerifiableCredential, StatusList } from '../src'
import { privateKeyJwk, signer, verifier } from './utils'

it.skip('examples', async () => {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const examples: any = {}
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

  const resolver = {
    resolve: async (id: string) => {
      if (id === 'https://example.com/credentials/status/3') {
        return statusList
      }
      throw new Error('unsupported status list.')
    },
  }

  examples.statusList = {
    [statusList]: await VerifiableCredential.verify({
      jwt: statusList,
      verifier,
      resolver,
    }),
  }

  const verifiableCredential = await VerifiableCredential.create({
    header: {
      alg: privateKeyJwk.alg,
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

  examples.verifiableCredential = {
    [verifiableCredential]: await VerifiableCredential.verify({
      jwt: verifiableCredential,
      verifier,
      resolver,
    }),
  }

  fs.writeFileSync('examples.spec.json', JSON.stringify(examples, null, 2))
})
