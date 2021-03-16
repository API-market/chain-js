import { Chain } from '../../../interfaces'
import { ChainFactory, ChainType } from '../../../index'
import { PolkadotChainEndpoint, PolkadotKeyPairType } from '../models'
import { ModelsCryptoAes } from '../../../models'

require('dotenv').config()

const { env } = process

const westendEndpoints: PolkadotChainEndpoint[] = [
  {
    url: 'wss://westend-rpc.polkadot.io',
  },
]

const createAccountOptions = {
  newKeysOptions: {
    password: '2233',
    keypairType: PolkadotKeyPairType.Ecdsa,
    encryptionOptions: ModelsCryptoAes.AesEncryptedDataStringBrand,
    salt: env.EOS_KYLIN_PK_SALT_V0,
  },
}

async function createAccount(paraChain: Chain) {
  try {
    await paraChain.connect()
    const createdAccount = paraChain.new.CreateAccount(createAccountOptions)
    await createdAccount.generateKeysIfNeeded()
    console.log('generatedKeys:', createdAccount.generatedKeys)
    console.log('address:', createdAccount.accountName)
  } catch (error) {
    console.log(error)
  }
}

async function newAccount(paraChain: Chain) {
  try {
    await paraChain.connect()
    const account = await paraChain.new.Account('5FkJuxShVBRJRirM3t3k5Y8XyDaxMi1c8hLdBsH2qeAYqAzF')
    console.log('account', account)
  } catch (error) {
    console.log(error)
  }
}

async function run() {
  try {
    const paraChainA = new ChainFactory().create(ChainType.PolkadotV1, westendEndpoints)
    // const paraChainB = new ChainFactory().create(ChainType.PolkadotV1, westendEndpoints)
    await createAccount(paraChainA)
    await newAccount(paraChainA)
    // const accountB = createAccount(paraChainB)
    // console.log('account', accountB)
  } catch (error) {
    console.log(error)
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
