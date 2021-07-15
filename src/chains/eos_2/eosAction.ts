import { hexToUint8Array } from 'eosjs/dist/eosjs-serialize'
import { throwNewError } from '../../errors'
import {
  isAnObject,
  isArrayLengthOne,
  isAString,
  isAUint8Array,
  isHexString,
  isNullOrEmpty,
  jsonParseAndRevive,
} from '../../helpers'
import { EosChainState } from './eosChainState'
import { EosActionStruct, EosRawTransaction, EosSerializedTransaction, EosTransactionOptions } from './models'

/** Helper class to ensure transaction actions properties are set correctly */
export class EosActionHelper {
  // properties stored as hex stings (not raw Buffers)

  private _options: EosTransactionOptions

  private _actions: EosActionStruct[]

  private _header: any

  private _raw: EosRawTransaction

  private _chainState: EosChainState

  /** Creates a new Action from 'human-readable' transfer or contact info
   *  OR from 'raw' data property
   *  Allows access to human-readable properties (method, parameters) or raw data (hex) */
  constructor(
    actionInput: EosActionStruct[] | EosSerializedTransaction[],
    options: EosTransactionOptions,
    chainState: EosChainState,
  ) {
    this._options = options
    this._chainState = chainState
    this.assertAndValidateEosActionInput(actionInput)
  }

  /** apply rules for imput params, set class private properties, throw if violation */
  private assertAndValidateEosActionInput(actionInput: EosActionStruct[] | EosSerializedTransaction[]) {
    if (isNullOrEmpty(actionInput)) return
    this.setActions(actionInput)
  }

  public get raw(): EosRawTransaction {
    if (!this._raw) return null
    return this._raw
  }

  public get actions(): EosActionStruct[] {
    return this._actions
  }

  public get header(): any {
    return this._header
  }

  private get options(): EosTransactionOptions {
    return this._options
  }

  /** Sets the Array of actions */
  public set actions(actions: EosActionStruct[]) {
    if (!this.isEosActionStructArray(actions)) {
      throwNewError('Invalid set actions input. Needs to be a valid EosActionStruct[]')
    }
    this._actions = actions
  }

  public setActions(actions: EosActionStruct[] | EosSerializedTransaction[]) {
    this._raw = null
    if (this.isSerializedEosTransaction(actions)) {
      this._raw = this.ensureSerializedIsRaw(actions[0] as EosSerializedTransaction)
      return
    }
    if (this.isEosActionStructArray(actions)) {
      this.actions = actions as EosActionStruct[]
      return
    }
    throwNewError('Invalid setActions input. Needs to be a valid EosActionStruct[] OR EosSerializedTransaction')
  }

  /** Accepts either an object where each value is the uint8 array value
   *     ex: {'0': 24, ... '3': 93 } => [24,241,213,93]
   *  OR a packed transaction as a string of hex bytes
   * */
  private ensureSerializedIsRaw = (serializedTransaction: EosSerializedTransaction): EosRawTransaction => {
    if (isAUint8Array(serializedTransaction)) return serializedTransaction as Uint8Array
    // if the trasaction data is a JSON array of bytes, convert to Uint8Array
    if (isAnObject(serializedTransaction)) {
      const trxLength = Object.keys(serializedTransaction).length
      let buf = new Uint8Array(trxLength)
      buf = Object.values(serializedTransaction) as any // should be a Uint8Array in this value
      return buf
    }
    // if transaction is a packed transaction (string of bytes), convert it into an Uint8Array of bytes
    if (serializedTransaction && isAString(serializedTransaction)) {
      const rawifiedTransaction = hexToUint8Array(serializedTransaction as string)
      return rawifiedTransaction
    }
    throw Error('Missing or malformed serializedTransaction (ensureSerializedIsRaw)')
  }

  public async setActionsAndHeaderFromRaw(): Promise<any> {
    this.assertIsConnected()
    const { actions, ...header } = await this._chainState.api.deserializeTransactionWithActions(this.raw)
    this._header = header
    this.actions = actions
  }

  public async serializeActions() {
    if (this.raw) return
    const { blocksBehind, expireSeconds } = this.options
    const transactOptions = { broadcast: false, sign: false, blocksBehind, expireSeconds }
    const { serializedTransaction } = await this._chainState.api.transact({ actions: this.actions }, transactOptions)
    this._raw = this.ensureSerializedIsRaw(serializedTransaction)
    this.setHeaderFromRaw()
  }

  /** Extract header from raw transaction body (eosjs refers to raw as serialized) */
  public setHeaderFromRaw(): void {
    // deserializeTransaction does not call the chain - just deserializes transation header and action names (not action data)
    const deRawified = this._chainState.api.deserializeTransaction(this.raw)
    delete deRawified.actions // remove parially deRawified actions
    this._header = deRawified
  }

  /** Returns a sign buffer using raw transaction body */
  public get signBuffer() {
    this.assertIsConnected()
    if (!this.raw) return null
    return Buffer.concat([
      Buffer.from(this._chainState?.chainId, 'hex'),
      Buffer.from(this.raw),
      Buffer.from(new Uint8Array(32)),
    ])
  }

  /** Throws if not yet connected to chain - via chain.connect() */
  private assertIsConnected(): void {
    if (!this._chainState?.isConnected) {
      throwNewError('Not connected to chain')
    }
  }

  private isEosActionStructArray(value: any) {
    if (isNullOrEmpty(value) || !Array.isArray(value)) return false
    if (!(value[0] as EosActionStruct).account) return false
    return true
  }

  private isSerializedEosTransaction(value: any) {
    if (isNullOrEmpty(value) || !Array.isArray(value)) return false
    // In case we have a Uint8Array in JSON format
    const serializedTrx = jsonParseAndRevive(JSON.stringify(value[0]))
    if (isAUint8Array(serializedTrx) || isHexString(serializedTrx)) {
      if (!isArrayLengthOne(value)) {
        throwNewError('For setting action as serializedTransaction the input array length has to be one.')
      }
      return true
    }
    return false
  }
}
