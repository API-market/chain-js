import { ConfirmType, Signature, PublicKey, PrivateKey, TransactionOptions, TransactionResult } from '../models'

/**
 * The Transaction interface declares the operations that all concrete chain (chain)transaction classes must implement
 */
export interface Transaction {
  /** Transaction's actions */
  actions: any
  /** Chain-specific and time-sensitive transaction header */
  header: any
  /** Transction options set in constructor */
  options: TransactionOptions
  /** Raw transaction body
   *  Note: Set via prepareToBeSigned() or setFromRaw() */
  raw: any
  /** Whether there is an attached signature for every authorization (e.g. account/permission) in all actions */
  hasAllRequiredSignatures: boolean
  /** Whether there are any signatures attached */
  hasAnySignatures: boolean
  /** Whether transaction has been prepared for signing (has raw body) */
  hasRaw: boolean
  /** Whether the transaction is a multi-signature transaction */
  isMultiSig: boolean
  // ** Whether transaction has been validated - via vaidate() */
  isValidated: boolean
  /** An array of authorizations (chain-specific result type) that do not have an attached signature
   *  Retuns null if no signatures are missing */
  missingSignatures: any[]
  /** An array of the unique set of authorizations needed for all actions in transaction */
  requiredAuthorizations: any[]

  resourcesRequired: any
  /** Signatures attached to transaction */
  signatures: string[]
  /** The transaction data needed to create a transaction signature.
   *  It should be signed with a private key. */
  signBuffer: any

  // supportsFee: boolean
  // estimatedCost: string
  // actualCost: string

  // maxFeeIncreasePercentage: number
  /** Whether the chain supports signing a transactions using a multi-signature account */
  supportsMultisigTransaction: boolean
  /** Add an action to the array of attached actions.
   *  Can't add action if any signatures are attached
   *  since it would invalidate existing signatures. */
  addAction(action: any, asFirstAction?: boolean): void
  /** Add a signature to the set of attached signatures. Automatically de-duplicates values. */
  addSignatures(signature: Signature[]): void
  /** Whether there is an attached signature for the publicKey for the authorization (e.g. account/permission)
   *  May need to call chain (async) to fetch publicKey(s) for authorization(s) */
  hasSignatureForAuthorization?(authorization: any): Promise<boolean>
  /** Whether there is an attached signature for the provided publicKey */
  hasSignatureForPublicKey(publicKey: PublicKey): boolean
  /** Internally creates Raw Transaction data.
   *  Requires at least one action set. Must be called before sign() */
  prepareToBeSigned(): Promise<void>

  // setDesiredFee(fee: string): void
  /** Set the body of the transaction using raw (hex) transaction data
   *  This is one of the ways to set the actions for the transaction */
  setFromRaw(raw: any): Promise<void>
  /** Broadcast a signed transaction to the chain
   *  waitForConfirm specifies whether to wait for a transaction to appear in a block (or irreversable block) before returning */
  send(waitForConfirm?: ConfirmType, communicationSettings?: any): Promise<TransactionResult>
  /** Sign the transaction body with private key(s) and add to attached signatures */
  sign(privateKeys: PrivateKey[]): Promise<void>

  // suggestedFee(priority: string): Promise<string>
  /** JSON representation of transaction data */
  toJson(): ConfirmType.None
  /** Verifies that all accounts and permisison for actions exist on chain.
   *  Throws if any problems */
  validate(): Promise<void>
}
