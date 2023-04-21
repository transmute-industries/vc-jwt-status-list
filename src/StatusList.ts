import * as jose from 'jose'
import moment from 'moment'
import { Bitstring } from './Bitstring'
import {
  CreateStatusList,
  VerifyStatusList,
  UpdateStatusList,
  StatusList2021Credential,
  StatusList2021CredentialHeader,
  CheckStatusList,
  JsonWebTokenStatusListVerifiableCredential,
  VerifiedJsonWebToken,
} from './types'

const statusListCredentialTemplate = {
  '@context': [
    'https://www.w3.org/ns/credentials/v2',
    'https://w3id.org/vc/status-list/2021/v1',
  ],
  id: 'https://example.com/credentials/status/3',
  type: ['VerifiableCredential', 'StatusList2021Credential'],
  issuer: 'did:example:12345',
  validFrom: '2021-04-05T14:27:40Z',
  credentialSubject: {
    id: 'https://example.com/status/3#list',
    type: 'StatusList2021',
    statusPurpose: 'revocation',
    encodedList:
      'H4sIAAAAAAAAA-3BMQEAAADCoPVPbQwfoAAAAAAAAAAAAAAAAAAAAIC3AYbSVKsAQAAA',
  },
}

export class StatusList {
  static create = async ({
    id,
    alg,
    iss,
    kid,
    iat,
    length,
    purpose,
    signer,
  }: CreateStatusList): Promise<JsonWebTokenStatusListVerifiableCredential> => {
    const template = JSON.parse(JSON.stringify(statusListCredentialTemplate))
    template.id = id
    template.validFrom = moment.unix(iat).toISOString()
    template.issuer = iss
    template.credentialSubject.id = id + '#list'
    template.credentialSubject.statusPurpose = purpose
    template.credentialSubject.encodedList = await new Bitstring({
      length,
    }).encodeBits()
    const jwt = await signer.sign({
      header: {
        alg,
        iss,
        kid,
        typ: 'vc+ld+jwt',
        cty: 'vc+ld+json',
      },
      claimset: template,
    })
    return jwt
  }

  static verify = async ({
    jwt,
    verifier,
  }: VerifyStatusList): Promise<VerifiedJsonWebToken> => {
    const { protectedHeader, payload } = await verifier.verify({
      jwt,
    })
    return { protectedHeader, payload }
  }

  static updateStatus = async ({
    jwt,
    position,
    purpose,
    status,
    signer,
  }: UpdateStatusList): Promise<JsonWebTokenStatusListVerifiableCredential> => {
    const claimset = await jose.decodeJwt(jwt)
    if (!claimset.credentialSubject) {
      throw new Error('JWT claimset is not StatusList2021Credential')
    }
    const statuListCredential = claimset as StatusList2021Credential
    if (statuListCredential.credentialSubject.statusPurpose !== purpose) {
      throw new Error('JWT claimset is not for ' + purpose)
    }
    const bs = new Bitstring({
      buffer: await Bitstring.decodeBits({
        encoded: statuListCredential.credentialSubject.encodedList,
      }),
    })
    bs.set(position, status)
    const header = await jose.decodeProtectedHeader(jwt)
    statuListCredential.credentialSubject.encodedList = await bs.encodeBits()
    return await signer.sign({
      header: header as StatusList2021CredentialHeader,
      claimset: statuListCredential,
    })
  }

  static checkStatus = async ({
    id,
    purpose,
    position,
    resolver,
    verifier,
  }: CheckStatusList): Promise<boolean> => {
    const jwt = await resolver.resolve(id)
    const { payload } = await verifier.verify({
      jwt,
    })
    if (!payload.credentialSubject) {
      throw new Error('JWT claimset is not StatusList2021Credential')
    }
    const statuListCredential = payload as StatusList2021Credential
    if (statuListCredential.credentialSubject.statusPurpose !== purpose) {
      throw new Error('JWT claimset is not for ' + purpose)
    }
    const bs = new Bitstring({
      buffer: await Bitstring.decodeBits({
        encoded: statuListCredential.credentialSubject.encodedList,
      }),
    })
    return bs.get(position)
  }
}
