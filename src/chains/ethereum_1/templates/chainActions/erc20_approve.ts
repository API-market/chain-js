// import { toHex } from 'web3-utils'
import {
  EthereumAddress,
  EthereumTransactionAction,
  EthereumChainActionType,
  EthereumDecomposeReturn,
} from '../../models'
import { erc20Abi } from '../abis/erc20Abi'
import { toEthereumAddress } from '../../helpers'

interface erc20ApproveParams {
  contractAddress: EthereumAddress
  from?: EthereumAddress
  spender: EthereumAddress
  value: number
}

export const composeAction = ({ contractAddress, from, spender, value }: erc20ApproveParams) => {
  const contract = {
    abi: erc20Abi,
    parameters: [spender, value],
    method: 'approve',
  }
  return {
    to: contractAddress,
    from,
    contract,
  }
}

export const decomposeAction = (action: EthereumTransactionAction): EthereumDecomposeReturn => {
  const { to, from, contract } = action
  if (to && contract && contract.abi === erc20Abi && contract.method === 'approve') {
    const returnData: Partial<erc20ApproveParams> = {
      contractAddress: to,
      from,
      spender: toEthereumAddress(contract.parameters[0] as string),
      value: contract.parameters[1] as number,
    }
    const partial = !returnData?.from
    return {
      chainActionType: EthereumChainActionType.Erc20Approve,
      args: returnData,
      partial,
    }
  }

  return null
}
