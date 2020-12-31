import { RpcError } from 'eosjs'
import {
  ChainActionType,
  ChainDate,
  ChainEntityName,
  ChainInfo,
  ChainType,
  CryptoCurve,
  PrivateKey,
  PublicKey,
  TransactionOptions,
} from '../../models'
import { NATIVE_CHAIN_TOKEN_SYMBOL, NATIVE_CHAIN_TOKEN_ADDRESS } from './eosConstants'
import { IChainStatic } from '../../interfaces'
import { ChainError, throwNewError } from '../../errors'
import * as eoscrypto from './eosCrypto'
import { EosChainState } from './eosChainState'
import { mapChainError } from './eosErrors'
import { composeAction } from './eosCompose'
import { decomposeAction } from './eosDecompose'
import { EosTransaction } from './eosTransaction'
import { EosCreateAccount } from './eosCreateAccount'
import { EosAccount } from './eosAccount'
import {
  isValidEosPrivateKey,
  isValidEosPublicKey,
  toEosPublicKey,
  toEosPrivateKey,
  toEosSignature,
  isValidEosEntityName,
  isValidEosAsset,
  isValidEosDate,
  toEosEntityName,
  toEosAsset,
  toEosDate,
  toEosSymbol,
} from './helpers'
import {
  EosActionStruct,
  EosChainSettings,
  EosEntityName,
  EosDate,
  EosCreateAccountOptions,
  EosDecomposeReturn,
  EosChainEndpoint,
  EosSymbol,
} from './models'
import { Asymmetric } from '../../crypto'

// DEVELOPER NOTE: The implementation of this class works around Typescripts limitation of not having a static member of an interface
// based on this approach - https://stackoverflow.com/questions/13955157/how-to-define-static-property-in-typescript-interface/59134002#59134002

/** Provides support for the EOS blockchain
 *  Provides EOS-specific implementations of the Chain interface
 *  Also includes some features only available on this platform */
const ChainEosV2: IChainStatic = class ChainEosV2 {
  // class ChainEosV2 implements IChainClass, static IChainStatic {
  private _endpoints: EosChainEndpoint[]

  private _settings: EosChainSettings

  private _chainState: EosChainState

  constructor(endpoints: EosChainEndpoint[], settings?: EosChainSettings) {
    this._endpoints = endpoints
    this._settings = settings
    this._chainState = new EosChainState(endpoints, settings)
  }

  /** Connect to chain endpoint to verify that it is operational and to get latest block info */

  public connect(): Promise<void> {
    return this._chainState.connect()
  }

  /** Return unique chain ID string */
  public get chainId(): string {
    this.assertIsConnected()
    return this._chainState.chainId
  }

  /** Retrieve lastest chain info including head block number and time */
  public get chainInfo(): ChainInfo {
    this.assertIsConnected()
    return this._chainState.chainInfo
  }

  /** Whether any info has been retrieved from the chain */
  public get isConnected(): boolean {
    return this._chainState?.isConnected
  }

  /** Get the token balance for an account from the chain
   *  If tokenAddress is not provided, uses eosio.token as default
   *  Returns a string representation of the value to accomodate large numbers */
  public async fetchBalance(
    account: EosEntityName,
    symbol: EosSymbol,
    tokenAddress: EosEntityName = ChainEosV2.nativeToken.tokenAddress,
  ): Promise<{ balance: string }> {
    return this._chainState.fetchBalance(account, symbol, tokenAddress)
  }

  /** Fetch data from an on-chain contract table */
  public async fetchContractData(
    contract: EosEntityName,
    table: string,
    owner: EosEntityName,
    indexNumber?: number,
    lowerRow?: number,
    upperRow?: number,
    limit?: number,
    reverseOrder?: boolean,
    showPayer?: boolean,
    keyType?: string,
  ): Promise<any> {
    return this._chainState.fetchContractData(
      contract,
      table,
      owner,
      indexNumber,
      lowerRow,
      upperRow,
      limit,
      reverseOrder,
      showPayer,
      keyType,
    )
  }

  public new = {
    /** Returns a new chain Account object
     * If an account name is provided, it will be fetched from the chain and loaded into the returned account object
     * Note: Does NOT create a new account - to create an account, use new.CreateAccount */
    Account: this.newAccount.bind(this),
    /** Return a new CreateAccount object used to help with creating a new chain account */
    CreateAccount: this.newCreateAccount.bind(this),
    /** Return a chain Transaction object used to compose and send transactions */
    Transaction: this.newTransaction.bind(this),
  }

  /** Returns a chain Account class
   * Note: Does NOT create a new account - to create an account, use new.CreateAccount */
  private async newAccount(accountName?: EosEntityName): Promise<EosAccount> {
    this.assertIsConnected()
    const account = new EosAccount(this._chainState)
    if (accountName) {
      await account.load(accountName)
    }
    return account
  }

  /** Return a ChainTransaction class used to compose and send transactions */
  private newCreateAccount(options?: EosCreateAccountOptions): EosCreateAccount {
    this.assertIsConnected()
    return new EosCreateAccount(this._chainState, options)
  }

  /** Return a ChainTransaction class used to compose and send transactions */
  private newTransaction(options?: TransactionOptions): EosTransaction {
    this.assertIsConnected()
    return new EosTransaction(this._chainState, options)
  }

  // STATIC MEMBERS

  /** Returns chain type enum - resolves to chain family as a string e.g. 'eos' */
  // eslint-disable-next-line class-methods-use-this
  public static get chainType(): ChainType {
    return ChainType.EosV2
  }

  /** Returns chain plug-in name */
  // eslint-disable-next-line class-methods-use-this
  public static get description(): string {
    return 'EOS 2.x Chain'
  }

  /** Returns chain native token symbol and default token contract address */
  public static get nativeToken(): { defaultUnit: string; symbol: EosSymbol; tokenAddress: EosEntityName } {
    return {
      defaultUnit: NATIVE_CHAIN_TOKEN_SYMBOL, // EOS doesnt use a seperate unit for the token - just returning the EOS symbol
      symbol: toEosSymbol(NATIVE_CHAIN_TOKEN_SYMBOL),
      tokenAddress: toEosEntityName(NATIVE_CHAIN_TOKEN_ADDRESS),
    }
  }

  /** Compose an object for a chain contract action */
  public static composeAction = async (actionType: ChainActionType, args: any): Promise<EosActionStruct> => {
    return composeAction(actionType, args)
  }

  /** Decompose a contract action and return the action type (if any) and its data */
  public static decomposeAction = async (action: EosActionStruct): Promise<EosDecomposeReturn[]> => {
    return decomposeAction(action)
  }

  // --------- Chain crytography functions */
  /** Primary cryptography curve used by this chain */
  public static cryptoCurve: CryptoCurve.Secp256k1

  /** Decrypts the encrypted value using a password, and optional parameters using AES algorithm and SHA256 hash function
   * Expects the encrypted value to be a stringified JSON object */
  public static decryptWithPassword = eoscrypto.decryptWithPassword

  /** Encrypts a string using a password and optional parameters using AES algorithm and SHA256 hash function
   * The returned, encrypted value is a stringified JSON object */
  public static encryptWithPassword = eoscrypto.encryptWithPassword

  /** Decrypts the encrypted value using a private key
   * The encrypted value is either a stringified JSON object or a JSON object
   * ... and must have been encrypted with the public key that matches the private ley provided */
  public static decryptWithPrivateKey = eoscrypto.decryptWithPrivateKey

  /** Encrypts a string using a public key
   * The encrypted result can be decrypted with the matching private key */
  public static encryptWithPublicKey = eoscrypto.encryptWithPublicKey

  /** Unwraps an object produced by encryptWithPublicKeys() - resulting in the original ecrypted string
   *  each pass uses a private keys from privateKeys array param
   *  put the keys in the same order as public keys provided to encryptWithPublicKeys() - they will be applied in the right (reverse) order
   *  The result is the decrypted string */
  public static decryptWithPrivateKeys = eoscrypto.decryptWithPrivateKeys

  /** Use assymmetric encryption with multiple public keys - wrapping with each
   *  Returns an array of results with the last one including the final cipertext
   *  Encrypts using publicKeys in the order they appear in the array */
  public static encryptWithPublicKeys = eoscrypto.encryptWithPublicKeys

  /** Generates and returns a new public/private key pair */
  public static generateKeyPair = eoscrypto.generateKeyPair

  /** Returns a public key given a signature and the original data was signed */
  public static getPublicKeyFromSignature = (
    signature: string | Buffer,
    data: string | Buffer,
    encoding: string,
  ): PublicKey => {
    return eoscrypto.getPublicKeyFromSignature(signature, data, encoding) as PublicKey
  }

  /** Verifies that the value is a valid, stringified JSON asymmetric encryption result */
  public static isAsymEncryptedDataString = Asymmetric.isAsymEncryptedDataString

  /** Verifies that the value is a valid, stringified JSON encryption result */
  public static isSymEncryptedDataString = eoscrypto.isSymEncryptedDataString

  /** Ensures that the value comforms to a well-formed private Key */
  public static isValidPrivateKey = (value: string): boolean => {
    return !!isValidEosPrivateKey(value)
  }

  /** Ensures that the value comforms to a well-formed Eos private Key */
  public static isValidEosPrivateKey = isValidEosPrivateKey

  /** Ensures that the value comforms to a well-formed public Key */
  public static isValidPublicKey = (value: string): boolean => {
    return !!isValidEosPublicKey(value)
  }

  /** Generate a signature given some data and a private key */
  public static sign = eoscrypto.sign

  /** Verify that the signed data was signed using the given key (signed with the private key for the provided public key) */
  public static verifySignedWithPublicKey = eoscrypto.verifySignedWithPublicKey

  /** Verifies that the value is a valid chain entity name (e.g. an account name) */
  public static isValidEntityName = (value: string): boolean => {
    return !!isValidEosEntityName(value)
  }

  /** Verifies that the value is a valid EOS entity name (e.g. an account name) */
  public static isValidEosEntityName = isValidEosEntityName

  /** Verifies that the value is a valid chain date */
  public static isValidDate = (value: string): boolean => {
    return !!isValidEosDate(value)
  }

  /** Verifies that the value is a valid EOS asset string */
  public static isValidEosAsset = isValidEosAsset

  /** Ensures that the value comforms to a well-formed EOS public Key */
  public static isValidEosPublicKey = isValidEosPublicKey

  /** Generates new owner and active key pairs (public and private)
   *  Encrypts private keys with provided password and optional params
   *  Returns: { publicKeys:{owner, active}, privateKeys:{owner, active}, privateKeysEncrypted:{owner, active} } */
  public static generateNewAccountKeysWithEncryptedPrivateKeys = eoscrypto.generateNewAccountKeysAndEncryptPrivateKeys

  // --------- Chain helper functions

  /** Verifies that the value is a valid EOS date */
  public static isValidEosDate = isValidEosDate

  /** Ensures that the value comforms to a well-formed EOS asset string */
  public static toEosAsset = toEosAsset

  /** Ensures that the value comforms to a well-formed chain entity name (e.g. an account name) */
  public static toEntityName = (value: string): ChainEntityName => {
    return toEosEntityName(value) as ChainEntityName
  }

  /** Ensures that the value comforms to a well-formed EOS entity name
   *  e.g. account, permission, or contract name */
  public static toEosEntityName = toEosEntityName

  /** Ensures that the value comforms to a well-formed chain date string */
  public static toDate = (value: string | Date | EosDate): ChainDate => {
    return toEosDate(value) as ChainDate
  }

  /** Ensures that the value comforms to a well-formed EOS date string */
  public static toEosDate = toEosDate

  /** Ensures that the value comforms to a well-formed public Key */
  public static toPublicKey = (value: string): PublicKey => {
    return toEosPublicKey(value) as PublicKey
  }

  /** Ensures that the value comforms to a well-formed EOS public Key */
  public static toEosPublicKey = toEosPublicKey

  /** Ensures that the value comforms to a well-formed EOS private Key */
  public static toEosPrivateKey = toEosPrivateKey

  /** Ensures that the value comforms to a well-formed private Key */
  public static toPrivateKey = (value: string): PrivateKey => {
    return toEosPrivateKey(value) as PrivateKey
  }

  /** Ensures that the value comforms to a well-formed stringified JSON encryption result */
  public static toAsymEncryptedDataString = Asymmetric.toAsymEncryptedDataString

  /** Ensures that the value comforms to a well-formed stringified JSON encryption result */
  public static toSymEncryptedDataString = eoscrypto.toSymEncryptedDataString

  /** Ensures that the value comforms to a well-formed EOS signature */
  public static toSignature = toEosSignature

  /** Ensures that the value comforms to a well-formed EOS signature */
  public static toEosSignature = toEosSignature

  /** Map error from chain into a well-known ChainError type */
  public static mapChainError = (error: RpcError | Error): ChainError => {
    return mapChainError(error)
  }

  /** Confirm that we've connected to the chain - throw if not */
  public assertIsConnected(): void {
    if (!this._chainState?.isConnected) {
      throwNewError('Not connected to chain')
    }
  }

  /** Access to underlying eosjs sdk
   *  Warning! You use chainjs functions wherever possible and only use this sdk as an escape hatch
   */
  public get eosjs() {
    return this._chainState?.eosjs
  }
}

export { ChainEosV2 }
