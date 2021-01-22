/* eslint-disable prettier/prettier */
/* eslint-disable max-len */
/* eslint-disable import/no-unresolved */
/* eslint-disable @typescript-eslint/camelcase */
/* eslint-disable @typescript-eslint/no-unused-vars */
/* eslint-disable no-console */

import fs from 'fs'
import { ChainFactory, ChainType } from '../../../index'
import { ChainActionType, ChainEndpoint, ConfirmType, TokenTransferParams } from '../../../models'
import {
  AlgorandActionAppCreate,
  AlgorandActionAppMultiPurpose,
  AlgorandActionAppUpdate,
  AlgorandChainActionType,
} from '../models'
import { toAlgorandPrivateKey, toAlgorandSymbol } from '../helpers'
import { toChainEntityName } from '../../../helpers'
import { ChainAlgorandV1 } from '../ChainAlgorandV1'
import { composedAppCreate } from '../tests/mockups/composedActions'

require('dotenv').config()

const { env } = process

const algoApiKey = env.AGLORAND_API_KEY || 'missing api key'
const algoMainnetEndpoints = [{
  url: 'https://mainnet-algorand.api.purestake.io/ps2',
  options: { indexerUrl: 'https://mainnet-algorand.api.purestake.io/idx2', headers: [{ 'x-api-key': algoApiKey }] },
}]
const algoTestnetEndpoints = [ {
  url: 'https://testnet-algorand.api.purestake.io/ps2',
  options: { indexerUrl: 'https://testnet-algorand.api.purestake.io/idx2', headers: [{ 'x-api-key': algoApiKey }] },
}]
const algoBetanetEndpoints = [{
  url: 'https://betanet-algorand.api.purestake.io/ps2',
  options: { indexerUrl: 'https://betanet-algorand.api.purestake.io/idx2', headers: [{ 'x-api-key': algoApiKey }] },
}]

const composeAppOptInParams: AlgorandActionAppMultiPurpose = {
  from: 'VBS2IRDUN2E7FJGYEKQXUAQX3XWL6UNBJZZJHB7CJDMWHUKXAGSHU5NXNQ',
  note: 'test optIn',
  appIndex: 13258116,
}

const composeAppCreateParams: Partial<AlgorandActionAppCreate> = {
  from: 'VBS2IRDUN2E7FJGYEKQXUAQX3XWL6UNBJZZJHB7CJDMWHUKXAGSHU5NXNQ',
  appNumLocalInts: 0,
  appNumLocalByteSlices: 0,
  appNumGlobalInts: 1,
  appNumGlobalByteSlices: 0,
  // appApprovalProgram & appClearProgram will be added in run()
}

const sampleRawNoOPTrx = {
  type:'appl',
  from:'6447K33DMECECFTWCWQ6SDJLY7EYM47G4RC5RCOKPTX5KA5RCJOTLAK7LU',
  fee:1000,
  firstRound:11395427,
  lastRound:11396427,
  genesisID:'testnet-v1.0',
  genesisHash:'SGO1GKSzyE7IEPItTxCByw9x8FmnrCDexi9/cOUJOiI=',
  appIndex:13258116, 
  appOnComplete:0, 
  appArgs: ['dHJhbnNmZXI=', 'MQ=='],
  appAccounts: ['IKSNMZFYNMXFBWB2JCPMEC4HT7UECC354UDCKNHQTNKF7WQG3UQW7YZHWA'],
}

async function run() {
  /** Create Algorand chain instance */
  
  const algoTest = new ChainFactory().create(ChainType.AlgorandV1, algoTestnetEndpoints) as ChainAlgorandV1
  await algoTest.connect()
  if (algoTest.isConnected) {
    console.log('Connected to %o', algoTest.chainId)
  }
  /** Compose and send transaction */
  const transaction = await algoTest.new.Transaction()

  // const { applications } = await algoTest.algoClientIndexer.searchForApplications().do()
  // console.log(applications)
  // const appList = applications.map((app:any) => app?.params )

  // const apps =  appList.filter((app: any) => app?.creator === 'VBS2IRDUN2E7FJGYEKQXUAQX3XWL6UNBJZZJHB7CJDMWHUKXAGSHU5NXNQ')
  // console.log(apps)

  // composeAppCreateParams.appApprovalProgram = await fs.readFileSync('../examples/application/approval_program.teal', 'utf8')
  // composeAppCreateParams.appClearProgram = await fs.readFileSync('../examples/application/clear_state_program.teal', 'utf8')
  // const action = await algoTest.composeAction(AlgorandChainActionType.AppOptIn, composeAppOptInParams)
  // console.log(composeAppCreateParams)
  // const action = await algoTest.composeAction(AlgorandChainActionType.AppCreate, composeAppCreateParams)
  // transaction.actions = [action]
  transaction.actions = [sampleRawNoOPTrx]
  // console.log('transaction actions: ', transaction.actions[0])
  const decomposed = await algoTest.decomposeAction(transaction.actions[0])
  // console.log('decomposed actions: ', decomposed)
  await transaction.prepareToBeSigned()
  await transaction.validate()
  await transaction.sign([toAlgorandPrivateKey(env.ALGOTESTNET_testaccount_PRIVATE_KEY)])
  console.log('missing signatures: ', transaction.missingSignatures)
  try{
    // console.log('send response: %o', JSON.stringify(await transaction.send(ConfirmType.After001)))
  }catch(err) {
    console.log(err)
  }
}

;(async () => {
  try {
    await run()
  } catch (error) {
    console.log('Error:', error)
  }
  process.exit()
})()

// ... For OptIn Test ...
// transaction actions:  {
//   name: 'Transaction',
//   tag: 'TX',
//   from: 'VBS2IRDUN2E7FJGYEKQXUAQX3XWL6UNBJZZJHB7CJDMWHUKXAGSHU5NXNQ',
//   fee: 1000,
//   firstRound: 11047681,
//   lastRound: 11048681,
//   note: 'test optIn',
//   genesisID: 'testnet-v1.0',
//   genesisHash: 'SGO1GKSzyE7IEPItTxCByw9x8FmnrCDexi9/cOUJOiI=',
//   appIndex: 13258116,
//   appOnComplete: 1,
//   type: 'appl',
//   flatFee: true
// }
// decomposed actions:  [
//   {
//     chainActionType: 'AppOptIn',
//     args: {
//       name: 'Transaction',
//       tag: 'TX',
//       from: 'VBS2IRDUN2E7FJGYEKQXUAQX3XWL6UNBJZZJHB7CJDMWHUKXAGSHU5NXNQ',
//       note: 'test optIn',
//       appIndex: 13258116,
//       appOnComplete: 1,
//       type: 'appl'
//     }
//   }
// ]