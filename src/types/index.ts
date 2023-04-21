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
    'https://www.w3.org/ns/credentials/v2',
    'https://w3id.org/vc/status-list/2021/v1',
  ]
  id: string
  type: ['VerifiableCredential', 'StatusList2021Credential']
  issuer: string
  validFrom: string
  credentialSubject: StatusList2021
}

export type StatusList2021Entry = {
  id: string
  type: StatusList2021Entry
  statusPurpose: StatusPurpose
  statusListIndex: string
  statusListCredential: string
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type CredentialSubject = Record<string, any>

export type VerifiableCredentialWithStatus = {
  '@context': [
    'https://www.w3.org/ns/credentials/v2',
    'https://w3id.org/vc/status-list/2021/v1',
  ]
  id: string
  type: string[]
  issuer: string
  validFrom: string
  credentialStatus: StatusList2021Entry
  credentialSubject: CredentialSubject
}

export type Verifier = {
  verify: (params: VerifyParameters) => Promise<VerifiedJsonWebToken>
}

export type Resolver = {
  resolve: (id: string) => Promise<string>
}

export type Signer = {
  sign: (params: SignParameters) => Promise<string>
}

export type JsonWebTokenVerifiableCredential = string

export type JsonWebTokenStatusListVerifiableCredential = string

export type CheckStatusList = {
  id: string
  purpose: StatusPurpose
  position: number
  resolver: Resolver
  verifier: Verifier
}

export type SignParameters = {
  header: StatusList2021CredentialHeader
  claimset: StatusList2021Credential
}

export type CreateStatusList = {
  id: string
  alg: 'ES256' | string
  iss: string
  kid: string
  iat: number
  length: number
  purpose: string
  signer: Signer
}

export type VerifyParameters = {
  jwt: string
}

export type VerifiedJsonWebToken = {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  protectedHeader: any
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  payload: any
}

export type VerifiedJsonWebTokenWithStatus = VerifiedJsonWebToken & {
  suspension?: boolean
  revocation?: boolean
}

export type VerifyStatusList = {
  jwt: JsonWebTokenStatusListVerifiableCredential
  verifier: Verifier
}

export type UpdateStatusList = {
  jwt: JsonWebTokenStatusListVerifiableCredential
  purpose: StatusPurpose
  position: number
  status: boolean
  signer: Signer
}

export type CreateVerifiableCredential = {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  header: any
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  claimset: any
  signer: Signer
}

export type VerifyVerifiableCredential = {
  jwt: JsonWebTokenVerifiableCredential
  resolver: Resolver
  verifier: Verifier
}

export type UpdateVerifiableCredentialStatus = {
  jwt: JsonWebTokenVerifiableCredential
  purpose: StatusPurpose
  status: boolean
  resolver: Resolver
  verifier: Verifier
  signer: Signer
}
