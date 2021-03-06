import { EosEntityName, EosPublicKey, EosChainActionType, EosActionStruct, EosDecomposeReturn } from '../../../models'
import {
  toEosEntityName,
  getFirstAuthorizationIfOnlyOneExists,
  toEosPublicKey,
  toEosEntityNameOrNull,
} from '../../../helpers'

const actionName = 'createoreacc'

export interface OreCreateAccountParams {
  accountName: EosEntityName
  creatorAccountName: EosEntityName
  creatorPermission: EosEntityName
  publicKeyActive: EosPublicKey
  publicKeyOwner: EosPublicKey
  tier: string
  referralAccountName: EosEntityName
}

export const composeAction = ({
  accountName,
  creatorAccountName,
  creatorPermission,
  publicKeyActive,
  publicKeyOwner,
  tier,
  referralAccountName,
}: OreCreateAccountParams): EosActionStruct => ({
  account: toEosEntityName('system.ore'),
  name: actionName,
  authorization: [
    {
      actor: creatorAccountName,
      permission: creatorPermission,
    },
  ],
  data: {
    creator: creatorAccountName,
    newname: accountName, // Some versions of the system contract are running a different version of the newaccount code
    ownerkey: publicKeyOwner,
    activekey: publicKeyActive,
    tier,
    referral: referralAccountName || '',
  },
})

export const decomposeAction = (action: EosActionStruct): EosDecomposeReturn => {
  const { name, data, authorization } = action

  if (name === actionName && data?.creator && data?.newname && data?.ownerkey && data?.activekey) {
    // If there's more than 1 authorization, we can't be sure which one is correct so we return null
    const auth = getFirstAuthorizationIfOnlyOneExists(authorization)
    const returnData: Partial<OreCreateAccountParams> = {
      accountName: toEosEntityName(data.newname),
      creatorAccountName: toEosEntityName(data.creator),
      creatorPermission: toEosEntityNameOrNull(auth?.permission),
      publicKeyActive: toEosPublicKey(data.ownerkey),
      publicKeyOwner: toEosPublicKey(data.activekey),
      tier: data.tier,
      referralAccountName: toEosEntityName(data.referral),
    }
    const partial = !returnData?.creatorPermission
    return {
      chainActionType: EosChainActionType.OreCreateAccount,
      args: returnData,
      partial,
    }
  }

  return null
}
