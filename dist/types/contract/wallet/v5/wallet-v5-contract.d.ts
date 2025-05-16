import BN from 'bn.js';
import { Cell } from '../../../boc/cell';
import { HttpProvider } from '../../../providers/http-provider';
import { AddressType } from '../../../utils/address';
import { Method } from '../../contract';
import { ExternalMessage } from '../wallet-contract';
import { WalletContract, WalletContractOptions, WalletContractMethods } from '../wallet-contract';

export interface WalletV5ContractMethods extends WalletContractMethods {
    getWalletId: () => Promise<number>;
    getSeqno: () => Promise<number>;
    getIsSignatureAuthAllowed: () => Promise<number>;
    getExtensions: () => Promise<Cell>;
    getExtensionsList: () => Promise<string[]>;
}

export interface DeployAndInstallPluginParams {
    secretKey: Uint8Array;
    seqno: number;
    pluginWc: number;
    amount: BN;
    stateInit: Cell;
    body: Cell;
    expireAt?: number;
}

export interface SetPluginParams {
    secretKey: Uint8Array;
    seqno: number;
    pluginAddress: AddressType;
    amount?: BN;
    queryId?: number;
    expireAt?: number;
}

export declare class WalletV5Contract extends WalletContract<WalletContractOptions, WalletV5ContractMethods> {
    constructor(provider: HttpProvider, options: WalletContractOptions);
    getName(): string;
    getWalletId(): Promise<number>;
    getSeqno(): Promise<number>;
    getIsSignatureAuthAllowed(): Promise<number>;
    getExtensions(): Promise<Cell>;
    getExtensionsList(): Promise<string[]>;
    static readonly codeCell: Cell;
}
