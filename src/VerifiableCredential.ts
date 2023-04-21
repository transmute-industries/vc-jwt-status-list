import { StatusList } from './StatusList'

import {
  CreateVerifiableCredential,
  VerifyVerifiableCredential,
  VerifiableCredentialWithStatus,
  UpdateVerifiableCredentialStatus,
  JsonWebTokenStatusListVerifiableCredential,
  VerifiedJsonWebTokenWithStatus,
} from './types'

export class VerifiableCredential {
  static create = async ({
    header,
    claimset,
    signer,
  }: CreateVerifiableCredential) => {
    return signer.sign({ header, claimset })
  }
  static verify = async ({
    jwt,
    verifier,
    resolver,
  }: VerifyVerifiableCredential) => {
    const credential = await verifier.verify({
      jwt,
    })
    if (credential.payload.credentialStatus) {
      const {
        credentialStatus,
      } = credential.payload as VerifiableCredentialWithStatus
      const statusListCheck = await StatusList.checkStatus({
        id: credentialStatus.statusListCredential,
        purpose: credentialStatus.statusPurpose,
        position: parseInt(credentialStatus.statusListIndex),
        verifier,
        resolver,
      })
      return {
        [credentialStatus.statusPurpose]: statusListCheck,
        ...credential,
      }
    }
    return credential as VerifiedJsonWebTokenWithStatus
  }

  static updateStatus = async ({
    jwt,
    purpose,
    status,
    resolver,
    verifier,
    signer,
  }: UpdateVerifiableCredentialStatus): Promise<
    JsonWebTokenStatusListVerifiableCredential
  > => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const { payload: credential }: any = await verifier.verify({
      jwt,
    })
    if (!credential.credentialStatus) {
      throw new Error('No credentialStatus to update')
    }
    const statusListCredential = await resolver.resolve(
      credential.credentialStatus.statusListCredential,
    )
    if (purpose !== credential.credentialStatus.statusPurpose) {
      throw new Error('credential does not support purpose: ' + status)
    }
    const updatedStatusList = await StatusList.updateStatus({
      jwt: statusListCredential,
      position: parseInt(credential.credentialStatus.statusListIndex),
      purpose: purpose,
      status: status,
      signer,
    })
    return updatedStatusList
  }
}
