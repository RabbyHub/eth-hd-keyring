import { HDKey } from 'ethereum-cryptography/hdkey';
import SimpleKeyring from '@rabby-wallet/eth-simple-keyring';

declare enum HDPathType {
    LedgerLive = "LedgerLive",
    Legacy = "Legacy",
    BIP44 = "BIP44"
}
interface Wallet {
    publicKey: Uint8Array;
    privateKey: Uint8Array;
}
interface DeserializeOption {
    hdPath?: string;
    mnemonic: string;
    activeIndexes?: number[];
    byImport?: boolean;
    index?: number;
    passphrase?: string;
    needPassphrase?: boolean;
    accounts?: string[];
    accountDetails?: Record<string, AccountDetail>;
    publicKey?: string;
    isSlip39?: boolean;
}
interface AccountDetail {
    hdPath: string;
    hdPathType: HDPathType;
    index: number;
    basePublicKey?: string;
}
declare class HdKeyring extends SimpleKeyring {
    static type: string;
    type: string;
    mnemonic: string | null;
    hdPath: string;
    hdWallet?: HDKey;
    wallets: Wallet[];
    activeIndexes: number[];
    index: number;
    page: number;
    perPage: number;
    byImport: boolean;
    publicKey: string;
    needPassphrase: boolean;
    accounts: string[];
    accountDetails: Record<string, AccountDetail>;
    passphrase?: string;
    isSlip39: boolean;
    constructor(opts?: DeserializeOption);
    serialize(): Promise<{
        mnemonic: string;
        /**
         * @deprecated
         */
        activeIndexes: number[];
        hdPath: string;
        byImport: boolean;
        index: number;
        needPassphrase: boolean;
        accounts: string[];
        accountDetails: Record<string, AccountDetail>;
        publicKey: string;
        isSlip39: boolean;
    }>;
    deserialize(opts?: DeserializeOption): string[] | Promise<any[]>;
    initFromMnemonic(mnemonic: string, passphrase?: string): void;
    private calcBasePublicKey;
    addAccounts(numberOfAccounts?: number): Promise<string[]>;
    activeAccounts(indexes: number[]): string[];
    getFirstPage(): Promise<{
        address: string;
        index: string;
    }[]>;
    getNextPage(): Promise<{
        address: string;
        index: string;
    }[]>;
    getPreviousPage(): Promise<{
        address: string;
        index: string;
    }[]>;
    getAddresses(start: number, end: number): any[];
    removeAccount(address: any): void;
    __getPage(increment: number): Promise<Array<{
        address: string;
        index: string;
    }>>;
    getAccounts(): Promise<string[]>;
    getInfoByAddress(address: string): AccountDetail | null;
    _addressFromIndex(i: number): [string, Wallet];
    private _addressFromPublicKey;
    generateMnemonic(): string;
    setHdPath(hdPath?: string): void;
    private getChildForIndex;
    private isLedgerLiveHdPath;
    private getPathForIndex;
    setPassphrase(passphrase: string): void;
    /**
     * if passphrase is correct, the publicKey will be the same as the stored one
     */
    checkPassphrase(passphrase: string): boolean;
    setAccountDetail: (address: string, accountDetail: AccountDetail) => void;
    getAccountDetail: (address: string) => AccountDetail;
    private getHDPathBase;
    setHDPathType(hdPathType: HDPathType): Promise<void>;
    getSeed(mnemonic: string, passphrase?: string): Uint8Array;
    slip39MnemonicToSeedSync(mnemonic: string, passphrase?: string): Uint8Array;
    static checkMnemonicIsSlip39(mnemonic: string): boolean;
    static slip39GetThreshold(shares: string[]): number;
    static slip39DecodeMnemonic(share: string): any;
    static validateMnemonic(mnemonic: string): boolean;
}

export { HdKeyring as default };
