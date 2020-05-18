/* Generated by ts-generator ver. 0.0.8 */
/* tslint:disable */

import { Contract, ContractTransaction, EventFilter, Signer } from "ethers";
import { Listener, Provider } from "ethers/providers";
import { Arrayish, BigNumber, BigNumberish, Interface } from "ethers/utils";
import {
  TransactionOverrides,
  TypedEventDescription,
  TypedFunctionDescription
} from ".";

interface IModuleCallsInterface extends Interface {
  functions: {
    nonce: TypedFunctionDescription<{ encode([]: []): string }>;

    readNonce: TypedFunctionDescription<{
      encode([_space]: [BigNumberish]): string;
    }>;

    execute: TypedFunctionDescription<{
      encode([_txs, _nonce, _signature]: [
        {
          delegateCall: boolean;
          revertOnError: boolean;
          gasLimit: BigNumberish;
          target: string;
          value: BigNumberish;
          data: Arrayish;
        }[],
        BigNumberish,
        Arrayish
      ]): string;
    }>;
  };

  events: {
    NonceChange: TypedEventDescription<{
      encodeTopics([_space, _newNonce]: [null, null]): string[];
    }>;

    TxFailed: TypedEventDescription<{
      encodeTopics([_tx, _reason]: [null, null]): string[];
    }>;
  };
}

export class IModuleCalls extends Contract {
  connect(signerOrProvider: Signer | Provider | string): IModuleCalls;
  attach(addressOrName: string): IModuleCalls;
  deployed(): Promise<IModuleCalls>;

  on(event: EventFilter | string, listener: Listener): IModuleCalls;
  once(event: EventFilter | string, listener: Listener): IModuleCalls;
  addListener(
    eventName: EventFilter | string,
    listener: Listener
  ): IModuleCalls;
  removeAllListeners(eventName: EventFilter | string): IModuleCalls;
  removeListener(eventName: any, listener: Listener): IModuleCalls;

  interface: IModuleCallsInterface;

  functions: {
    nonce(): Promise<BigNumber>;

    readNonce(_space: BigNumberish): Promise<BigNumber>;

    execute(
      _txs: {
        delegateCall: boolean;
        revertOnError: boolean;
        gasLimit: BigNumberish;
        target: string;
        value: BigNumberish;
        data: Arrayish;
      }[],
      _nonce: BigNumberish,
      _signature: Arrayish,
      overrides?: TransactionOverrides
    ): Promise<ContractTransaction>;
  };

  nonce(): Promise<BigNumber>;

  readNonce(_space: BigNumberish): Promise<BigNumber>;

  execute(
    _txs: {
      delegateCall: boolean;
      revertOnError: boolean;
      gasLimit: BigNumberish;
      target: string;
      value: BigNumberish;
      data: Arrayish;
    }[],
    _nonce: BigNumberish,
    _signature: Arrayish,
    overrides?: TransactionOverrides
  ): Promise<ContractTransaction>;

  filters: {
    NonceChange(_space: null, _newNonce: null): EventFilter;

    TxFailed(_tx: null, _reason: null): EventFilter;
  };

  estimate: {
    nonce(): Promise<BigNumber>;

    readNonce(_space: BigNumberish): Promise<BigNumber>;

    execute(
      _txs: {
        delegateCall: boolean;
        revertOnError: boolean;
        gasLimit: BigNumberish;
        target: string;
        value: BigNumberish;
        data: Arrayish;
      }[],
      _nonce: BigNumberish,
      _signature: Arrayish
    ): Promise<BigNumber>;
  };
}
