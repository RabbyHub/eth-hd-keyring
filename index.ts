// import Wallet, { hdkey } from 'ethereumjs-wallet';
import { HDKey } from 'ethereum-cryptography/hdkey';
import SimpleKeyring from '@rabby-wallet/eth-simple-keyring';
import * as bip39 from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import * as sigUtil from 'eth-sig-util';
import { bytesToHex, publicToAddress, privateToPublic } from '@ethereumjs/util';

// Options:
const type = 'HD Key Tree';

enum HDPathType {
  LedgerLive = 'LedgerLive',
  Legacy = 'Legacy',
  BIP44 = 'BIP44',
}

const HD_PATH_BASE = {
  [HDPathType.BIP44]: "m/44'/60'/0'/0",
  [HDPathType.Legacy]: "m/44'/60'/0'",
  [HDPathType.LedgerLive]: "m/44'/60'/0'/0/0",
};

const HD_PATH_TYPE = {
  [HD_PATH_BASE[HDPathType.BIP44]]: HDPathType.BIP44,
  [HD_PATH_BASE[HDPathType.Legacy]]: HDPathType.Legacy,
  [HD_PATH_BASE[HDPathType.LedgerLive]]: HDPathType.LedgerLive,
};

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
}

interface AccountDetail {
  hdPath: string;
  hdPathType: HDPathType;
  index: number;
}

class HdKeyring extends SimpleKeyring {
  static type = type;

  type = type;
  mnemonic: string | null = null;
  hdPath = HD_PATH_BASE[HDPathType.BIP44];
  hdWallet?: HDKey;
  wallets: Wallet[] = [];
  _index2wallet: Record<number, [string, Wallet]> = {};
  activeIndexes: number[] = [];
  index = 0;
  page = 0;
  perPage = 5;
  byImport = false;
  publicKey: string = '';
  needPassphrase = false;
  accounts: string[] = [];
  accountDetails: Record<string, AccountDetail> = {};

  /* PUBLIC METHODS */
  constructor(opts: DeserializeOption = {} as any) {
    super();
    this.deserialize(opts);
  }

  serialize() {
    return Promise.resolve({
      mnemonic: this.mnemonic,
      /**
       * @deprecated
       */
      activeIndexes: this.activeIndexes,
      hdPath: this.hdPath,
      byImport: this.byImport,
      index: this.index,
      needPassphrase: this.needPassphrase,
      accounts: this.accounts,
      accountDetails: this.accountDetails,
      publicKey: this.publicKey,
    });
  }

  deserialize(opts: DeserializeOption = {} as any) {
    this.wallets = [];
    this.mnemonic = null;
    this.hdPath = opts.hdPath || HD_PATH_BASE[HDPathType.BIP44];
    this.byImport = !!opts.byImport;
    this.index = opts.index || 0;
    this.needPassphrase = opts.needPassphrase || !opts.passphrase;
    this.accounts = opts.accounts || [];
    this.accountDetails = opts.accountDetails || {};
    this.publicKey = opts.publicKey || '';

    if (opts.mnemonic) {
      this.initFromMnemonic(opts.mnemonic, opts.passphrase);
    }

    // activeIndexes is deprecated, if accounts is not empty, use accounts
    if (!this.accounts.length && opts.activeIndexes) {
      return this.activeAccounts(opts.activeIndexes);
    }

    return Promise.resolve([]);
  }

  initFromMnemonic(mnemonic, passphrase?: string) {
    this.mnemonic = mnemonic;
    this._index2wallet = {};
    const seed = bip39.mnemonicToSeedSync(mnemonic, passphrase);
    this.hdWallet = HDKey.fromMasterSeed(seed);
    if (!this.publicKey) {
      const root = this.hdWallet!.derive(HD_PATH_BASE[HDPathType.BIP44]);
      this.publicKey = bytesToHex(root.publicKey!);
    }
  }

  addAccounts(numberOfAccounts = 1) {
    if (!this.hdWallet) {
      this.initFromMnemonic(bip39.generateMnemonic(wordlist));
    }

    let count = numberOfAccounts;
    let currentIdx = 0;
    const addresses: string[] = [];

    while (count) {
      const [address, wallet] = this._addressFromIndex(currentIdx);
      if (this.wallets.includes(wallet)) {
        currentIdx++;
      } else {
        this.wallets.push(wallet);
        addresses.push(address);
        // this.activeIndexes.push(currentIdx);
        this.setAccountDetail(address, {
          hdPath: this.hdPath,
          hdPathType: HD_PATH_TYPE[this.hdPath],
          index: currentIdx,
        });
        count--;
      }
      if (!this.accounts.includes(address)) {
        this.accounts.push(address);
      }
    }

    return Promise.resolve(addresses);
  }

  activeAccounts(indexes: number[]) {
    const accounts: string[] = [];
    for (const index of indexes) {
      const [address, wallet] = this._addressFromIndex(index);
      this.wallets.push(wallet);
      this.activeIndexes.push(index);

      accounts.push(address);
      // hdPath is BIP44
      this.setAccountDetail(address, {
        hdPath: this.hdPath,
        hdPathType: HD_PATH_TYPE[this.hdPath],
        index: index,
      });

      if (!this.accounts.includes(address)) {
        this.accounts.push(address);
      }
    }

    return accounts;
  }

  getFirstPage() {
    this.page = 0;
    return this.__getPage(1);
  }

  getNextPage() {
    return this.__getPage(1);
  }

  getPreviousPage() {
    return this.__getPage(-1);
  }
  getAddresses(start: number, end: number) {
    const from = start;
    const to = end;
    const accounts: any[] = [];
    for (let i = from; i < to; i++) {
      const [address] = this._addressFromIndex(i);
      accounts.push({
        address,
        index: i + 1,
      });
    }
    return accounts;
  }

  removeAccount(address) {
    super.removeAccount(address);
    const index = this.getIndexByAddress(address);
    this.activeIndexes = this.activeIndexes.filter((i) => i !== index);
  }

  async __getPage(increment: number): Promise<
    Array<{
      address: string;
      index: string;
    }>
  > {
    this.page += increment;

    if (!this.page || this.page <= 0) {
      this.page = 1;
    }

    const from = (this.page - 1) * this.perPage;
    const to = from + this.perPage;

    const accounts: any[] = [];

    for (let i = from; i < to; i++) {
      const [address] = this._addressFromIndex(i);
      accounts.push({
        address,
        index: i + 1,
      });
    }

    return accounts;
  }

  getAccounts() {
    if (this.accounts?.length) {
      return Promise.resolve(this.accounts);
    }

    return Promise.resolve(
      this.wallets.map((w) => {
        return sigUtil.normalize(this._addressFromPublicKey(w.publicKey));
      }),
    );
  }

  getIndexByAddress(address: string): number | null {
    for (const key in this._index2wallet) {
      if (this._index2wallet[key][0].toLowerCase() === address.toLowerCase()) {
        return Number(key);
      }
    }
    return null;
  }

  _addressFromIndex(i: number): [string, Wallet] {
    if (!this._index2wallet[i]) {
      const child = this.getChildForIndex(i);
      const wallet = {
        publicKey: privateToPublic(child.privateKey!),
        privateKey: child.privateKey!,
      };
      const address = sigUtil.normalize(
        this._addressFromPublicKey(wallet.publicKey),
      );
      this._index2wallet[i] = [address, wallet];
    }

    return this._index2wallet[i];
  }

  private _addressFromPublicKey(publicKey: Uint8Array) {
    return bytesToHex(publicToAddress(publicKey, true)).toLowerCase();
  }

  generateMnemonic() {
    return bip39.generateMnemonic(wordlist);
  }

  setHdPath(hdPath = HD_PATH_BASE[HDPathType.BIP44]) {
    this.hdPath = hdPath;
  }

  private getChildForIndex(index: number) {
    return this.hdWallet!.derive(this.getPathForIndex(index));
  }

  private isLedgerLiveHdPath() {
    return this.hdPath === HD_PATH_BASE[HDPathType.LedgerLive];
  }

  private getPathForIndex(index) {
    return this.isLedgerLiveHdPath()
      ? `m/44'/60'/${index}'/0/0`
      : `${this.hdPath}/${index}`;
  }

  setPassphrase(passphrase: string) {
    this.initFromMnemonic(this.mnemonic, passphrase);

    for (const acc of this.accounts) {
      const detail = this.getAccountDetail(acc);
      this.setHdPath(detail.hdPath);
      const [address, wallet] = this._addressFromIndex(detail.index);
      if (address.toLowerCase() === acc.toLowerCase()) {
        this.wallets.push(wallet);
      }
    }
  }

  /**
   * if passphrase is correct, the publicKey will be the same as the stored one
   */
  checkPassphrase(passphrase: string) {
    const seed = bip39.mnemonicToSeedSync(this.mnemonic!, passphrase);
    const hdWallet = HDKey.fromMasterSeed(seed);
    const root = hdWallet!.derive(HD_PATH_BASE[HDPathType.BIP44]);
    const currentPublickey = bytesToHex(root.publicKey!);

    return this.publicKey === currentPublickey;
  }

  setAccountDetail = (address: string, accountDetail: AccountDetail) => {
    this.accountDetails = {
      ...this.accountDetails,
      [address.toLowerCase()]: accountDetail,
    };
  };

  getAccountDetail = (address: string) => {
    return this.accountDetails[address.toLowerCase()];
  };
}

export default HdKeyring;
