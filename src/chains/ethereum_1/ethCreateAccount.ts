import { EthereumChainState } from './ethChainState'
import { throwNewError } from '../../errors'
import { CreateAccount } from '../../interfaces'
import {
  getEthereumAddressFromPublicKey,
  generateNewAccountKeysAndEncryptPrivateKeys,
  isValidPublicKey,
} from './ethCrypto'
import { isNullOrEmpty, notSupported } from '../../helpers'
import { EthereumAddress, EthereumPublicKey } from './models/cryptoModels'
import { EthereumAccountStruct } from './models/ethStructures'
import { EthereumNewAccountType, EthereumCreateAccountOptions } from './models/accountModels'
import { EthereumEntityName } from './models/generalModels'

/** Helper class to compose a transction for creating a new chain account
 *  Handles native accounts
 *  Generates new account keys if not provide */
export class EthereumCreateAccount implements CreateAccount {
  private _accountName: EthereumAddress

  private _chainState: EthereumChainState

  private _didRecycleAccount: boolean

  private _accountType: EthereumNewAccountType

  private _options: EthereumCreateAccountOptions

  requiresTransaction: boolean = false

  private _generatedKeys: EthereumAccountStruct

  constructor(chainState: EthereumChainState, options?: EthereumCreateAccountOptions) {
    this._chainState = chainState
    this._options = options
  }

  /** Compose a transaction to send to the chain to create a new account
   * Ethereum does not require a create account transaction to be sent to the chain
   */
  async composeTransaction(): Promise<void> {
    notSupported()
  }

  /** Determine if desired account name is usable for a new account.
   */
  async determineNewAccountName(): Promise<any> {
    notSupported()
  }

  /** extract keys from options
   *  Returns publicKeys */
  private getPublicKeysFromOptions(): EthereumPublicKey {
    const { publicKey } = this._options || {}
    if (!publicKey) {
      return null
    }
    return publicKey
  }

  /** Checks create options - if publicKeys are missing,
   *  autogenerate them and add them to options */
  async generatePublicKeysIfNeeded() {
    let publicKey: EthereumPublicKey
    this.assertValidOptionPublicKeys()
    this.assertValidOptionNewKeys()
    // get keys from options or generate
    publicKey = this.getPublicKeysFromOptions()
    if (!publicKey) {
      publicKey = await this.generateNewKeys()
    }
    this._accountName = await getEthereumAddressFromPublicKey(publicKey)
    this._accountType = EthereumNewAccountType.Native
  }

  private async generateNewKeys() {
    const { newKeysOptions } = this._options || {}
    const { password, salt } = newKeysOptions || {}

    this._generatedKeys = await generateNewAccountKeysAndEncryptPrivateKeys(password, salt, {})
    const newPublicKey = this._generatedKeys?.publicKey
    return newPublicKey
  }

  /* Not supported for Ethereum */
  async generateAccountName(): Promise<EthereumEntityName> {
    notSupported()
    return null
  }

  /* Ethereum accounts do not have the concept of existing on chain */
  async doesAccountExist(): Promise<any> {
    notSupported()
    return null
  }

  /** Not supported */
  generateAccountNameString = (): any => {
    notSupported()
  }

  /** ETH does not require the chain to execute a createAccount transaction
   *  to create the account structure on-chain */
  requiresTransactionToCreateAccount = (): boolean => {
    return false
  }

  private assertValidOptionPublicKeys() {
    const { publicKey } = this._options
    if (publicKey && !isValidPublicKey(publicKey)) {
      throwNewError('Invalid Option - Provided publicKey isnt valid')
    }
  }

  private assertValidOptionNewKeys() {
    const { newKeysOptions } = this._options
    const { password, salt } = newKeysOptions || {}
    if (isNullOrEmpty(password) || isNullOrEmpty(salt)) {
      throwNewError('Invalid Option - You must provide a password AND salt to generate new keys')
    }
  }

  /** Account name for the account to be created
   *  May be automatically generated (or otherwise changed) by composeTransaction() */
  get accountName(): any {
    return this._accountName
  }

  /** Account type to be created */
  get accountType(): EthereumNewAccountType {
    return this._accountType
  }

  /** Account creation options */
  get options() {
    return this._options
  }

  /** Account will be recycled (accountName must be specified via composeTransaction()
   * This is set by composeTransaction()
   * ... if the account name provided has the 'unused' key as its active public key */
  get didRecycleAccount() {
    return this._didRecycleAccount
  }

  /** The keys that were generated as part of the account creation process
   *  IMPORTANT: Be sure to always read and store these keys after creating an account
   *  This is the only way to retrieve the auto-generated private keys after an account is created */
  get generatedKeys() {
    if (this._generatedKeys) {
      return this._generatedKeys
    }
    return null
  }

  /** Ethereum account creation doesn't require any on chain transactions.
   * Hence there is no transaction object attached to EthereumCreateAccount class
   */
  get transaction(): any {
    throwNewError('Ethereum account creation does not require any on chain transactions')
    return null
  }
}