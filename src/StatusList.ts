import * as jose from 'jose'
import moment from 'moment'
import { Bitstring } from './Bitstring'

export type StatusPurpose = 'revocation' | 'suspension' | string

export type StatusList2021 = {
  id: string
  type: 'StatusList2021'
  statusPurpose: StatusPurpose
  encodedList: string
}

export type StatusList2021CredentialHeader = {
  alg: 'ES256' | string
  iss: string
  kid: string
  typ: 'vc+ld+jwt'
  cty: 'vc+ld+json'
}

export type StatusList2021Credential = {
  '@context': [
    'https://www.w3.org/2018/credentials/v1',
    'https://w3id.org/vc/status-list/2021/v1',
  ]
  id: string
  type: ['VerifiableCredential', 'StatusList2021Credential']
  issuer: string
  issued: string
  credentialSubject: StatusList2021
}

export type CheckStatusList = {
  id: string
  purpose: StatusPurpose
  position: number
  resolver: {
    resolve: (id: string) => Promise<string>
  }
  verifier: {
    verify: (params: StatusListVerifyParameters) => Promise<VerifiedJwt>
  }
}

export type StatusListSignParameters = {
  header: StatusList2021CredentialHeader
  payload: StatusList2021Credential
}

export type CreateStatusList = {
  id: string
  alg: 'ES256' | string
  iss: string
  kid: string
  iat: number
  length: number
  purpose: string
  signer: {
    sign: (params: StatusListSignParameters) => Promise<string>
  }
}

export type StatusListVerifyParameters = {
  jwt: string
}

export type VerifiedJwt = {
  protectedHeader: StatusList2021CredentialHeader
  payload: StatusList2021Credential
}

export type VerifyStatusList = {
  jwt: string
  verifier: {
    verify: (params: StatusListVerifyParameters) => Promise<VerifiedJwt>
  }
}

export type UpdateStatusList = {
  jwt: string
  purpose: StatusPurpose
  position: number
  status: boolean
  signer: {
    sign: (params: StatusListSignParameters) => Promise<string>
  }
}

const statusListCredentialTemplate = {
  '@context': [
    'https://www.w3.org/2018/credentials/v1',
    'https://w3id.org/vc/status-list/2021/v1',
  ],
  id: 'https://example.com/credentials/status/3',
  type: ['VerifiableCredential', 'StatusList2021Credential'],
  issuer: 'did:example:12345',
  issued: '2021-04-05T14:27:40Z',
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
  }: CreateStatusList) => {
    const template = JSON.parse(JSON.stringify(statusListCredentialTemplate))
    template.id = id
    template.issued = moment.unix(iat).toISOString()
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
      payload: template,
    })
    return jwt
  }

  static verify = async ({ jwt, verifier }: VerifyStatusList) => {
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
  }: UpdateStatusList) => {
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
      payload: statuListCredential,
    })
  }

  static checkStatus = async ({
    id,
    purpose,
    position,
    resolver,
    verifier,
  }: CheckStatusList) => {
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
