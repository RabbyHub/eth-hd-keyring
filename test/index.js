const assert = require('assert');
const {
  normalize,
  personalSign,
  recoverPersonalSignature,
  recoverTypedSignature,
  signTypedData,
  SignTypedDataVersion,
} = require('@metamask/eth-sig-util');
const ethUtil = require('ethereumjs-util');
const newEthUtil = require('@ethereumjs/util');
const HdKeyring = require('..').default;
// Sample account:
const privKeyHex =
  'b8a9c05beeedb25df85f8d641538cbffedf67216048de9c678ee26260eb91952';

const sampleMnemonic =
  'finish oppose decorate face calm tragic certain desk hour urge dinosaur mango';
const firstAcct = '0x1c96099350f13d558464ec79b9be4445aa0ef579';
const secondAcct = '0x1b00aed43a693f3a957f9feb5cc08afa031e37a0';

describe('hd-keyring', function () {
  let keyring = new HdKeyring();
  beforeEach(function () {
    keyring = new HdKeyring();
  });

  describe('constructor', function () {
    it('constructs', function (done) {
      keyring = new HdKeyring({
        mnemonic: sampleMnemonic,
        activeIndexes: [0, 1],
      });

      keyring.getAccounts().then((accounts) => {
        assert.equal(accounts[0], firstAcct);
        assert.equal(accounts[1], secondAcct);
        done();
      });
    });
  });

  describe('Keyring.type', function () {
    it('is a class property that returns the type string.', function () {
      const { type } = HdKeyring;
      assert.equal(typeof type, 'string');
    });
  });

  describe('#type', function () {
    it('returns the correct value', function () {
      const { type } = keyring;
      const correct = HdKeyring.type;
      assert.equal(type, correct);
    });
  });

  describe('#serialize empty wallets.', function () {
    it('serializes a new mnemonic', function () {
      keyring.serialize().then((output) => {
        // assert.equal(output.numberOfAccounts, 0);
        assert.equal(output.mnemonic, null);
      });
    });
  });

  describe('#deserialize a private key', function () {
    it('serializes what it deserializes', function (done) {
      keyring.deserialize({
        mnemonic: sampleMnemonic,
        activeIndexes: [0],
      });
      assert.equal(keyring.wallets.length, 1, 'restores two accounts');
      keyring.addAccounts(1);
      keyring
        .getAccounts()
        .then((accounts) => {
          assert.equal(accounts[0], firstAcct);
          assert.equal(accounts[1], secondAcct);
          assert.equal(accounts.length, 2);
          return keyring.serialize();
        })
        .then((serialized) => {
          assert.equal(serialized.mnemonic, sampleMnemonic);
          done();
        });
    });
  });

  describe('#addAccounts', function () {
    describe('with no arguments', function () {
      it('creates a single wallet', function (done) {
        keyring.addAccounts().then(() => {
          assert.equal(keyring.wallets.length, 1);
          done();
        });
      });
    });

    describe('with a numeric argument', function () {
      it('creates that number of wallets', function (done) {
        keyring.addAccounts(3).then(() => {
          assert.equal(keyring.wallets.length, 3);
          done();
        });
      });
    });
  });

  describe('#getAccounts', function () {
    it('calls getAddress on each wallet', function (done) {
      // Push a mock wallet
      const desiredOutput = '0x410264A247892c3b2912AeE58236036A82CA209e';
      keyring.wallets.push({
        publicKey: newEthUtil.importPublic(
          newEthUtil.hexToBytes(
            '0x0220381189b226eae955cf7331b649be61b6ec55ea678cb30c7371e9e07dc200bd',
          ),
        ),
        privateKey: newEthUtil.hexToBytes(
          '0x504560704904af362cab963188f571bccb1498f6ab5113b6bd8d76b6c53a963e',
        ),
      });

      keyring.getAccounts().then((output) => {
        assert.equal(output[0].toLowerCase(), desiredOutput.toLowerCase());
        assert.equal(output.length, 1);
        done();
      });
    });
  });

  describe('#signPersonalMessage', function () {
    it('returns the expected value', function (done) {
      const address = firstAcct;
      const message = '0x68656c6c6f20776f726c64';

      keyring.deserialize({
        mnemonic: sampleMnemonic,
        activeIndexes: [0],
      });

      keyring
        .signPersonalMessage(address, message)
        .then((signature) => {
          assert.notEqual(signature, message, 'something changed');

          const restored = recoverPersonalSignature({
            data: message,
            signature,
          });

          assert.equal(restored, normalize(address), 'recovered address');
          done();
        })
        .catch((reason) => {
          console.error('failed because', reason);
        });
    });
  });

  describe('#signTypedData', function () {
    it('can recover a basic signature', async function () {
      Buffer.from(privKeyHex, 'hex');

      const typedData = [
        {
          type: 'string',
          name: 'message',
          value: 'Hi, Alice!',
        },
      ];
      await keyring.addAccounts(1);
      const addresses = await keyring.getAccounts();
      const address = addresses[0];
      const signature = await keyring.signTypedData(address, typedData);
      const restored = recoverTypedSignature({
        data: typedData,
        signature,
        version: SignTypedDataVersion.V1,
      });
      assert.equal(restored, address, 'recovered address');
    });
  });

  describe('#signTypedData_v1', function () {
    const typedData = [
      {
        type: 'string',
        name: 'message',
        value: 'Hi, Alice!',
      },
    ];

    it('signs in a compliant and recoverable way', async function () {
      await keyring.addAccounts(1);
      const addresses = await keyring.getAccounts();
      const address = addresses[0];
      const signature = await keyring.signTypedData_v1(address, typedData);
      const restored = recoverTypedSignature({
        data: typedData,
        signature,
        version: SignTypedDataVersion.V1,
      });
      assert.equal(restored, address, 'recovered address');
    });
  });

  describe('#signTypedData_v3', function () {
    it('signs in a compliant and recoverable way', async function () {
      const typedData = {
        types: {
          EIP712Domain: [],
        },
        domain: {},
        primaryType: 'EIP712Domain',
        message: {},
      };

      await keyring.deserialize({
        mnemonic: sampleMnemonic,
        activeIndexes: [0],
      });
      const addresses = await keyring.getAccounts();
      const address = addresses[0];
      const signature = await keyring.signTypedData_v3(address, typedData);
      const restored = recoverTypedSignature({
        data: typedData,
        signature,
        version: SignTypedDataVersion.V3,
      });
      assert.equal(restored, address, 'recovered address');
    });
  });

  describe('#signTypedData_v3 signature verification', function () {
    it('signs in a recoverable way.', async function () {
      const typedData = {
        types: {
          EIP712Domain: [
            { name: 'name', type: 'string' },
            { name: 'version', type: 'string' },
            { name: 'chainId', type: 'uint256' },
            { name: 'verifyingContract', type: 'address' },
          ],
          Person: [
            { name: 'name', type: 'string' },
            { name: 'wallet', type: 'address' },
          ],
          Mail: [
            { name: 'from', type: 'Person' },
            { name: 'to', type: 'Person' },
            { name: 'contents', type: 'string' },
          ],
        },
        primaryType: 'Mail',
        domain: {
          name: 'Ether Mail',
          version: '1',
          chainId: 1,
          verifyingContract: '0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC',
        },
        message: {
          from: {
            name: 'Cow',
            wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
          },
          to: {
            name: 'Bob',
            wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
          },
          contents: 'Hello, Bob!',
        },
      };

      await keyring.addAccounts(1);
      const addresses = await keyring.getAccounts();
      const address = addresses[0];
      const signature = await keyring.signTypedData_v3(address, typedData);
      const restored = recoverTypedSignature({
        data: typedData,
        signature,
        version: SignTypedDataVersion.V3,
      });
      assert.equal(restored, address, 'recovered address');
    });
  });

  describe('custom hd paths', function () {
    it('can deserialize with an hdPath param and generate the same accounts.', function (done) {
      const hdPathString = `m/44'/60'/0'/0`;

      keyring.deserialize({
        mnemonic: sampleMnemonic,
        activeIndexes: [0],
        hdPath: hdPathString,
      });

      keyring
        .getAccounts()
        .then((addresses) => {
          assert.equal(addresses[0], firstAcct);
          return keyring.serialize();
        })
        .then((serialized) => {
          assert.equal(serialized.hdPath, hdPathString);
          done();
        })
        .catch((reason) => {
          console.error('failed because', reason);
        });
    });

    it('can deserialize with an hdPath param and generate different accounts.', function (done) {
      const hdPathString = `m/44'/60'/0'/1`;

      keyring.deserialize({
        mnemonic: sampleMnemonic,
        activeIndexes: [0],
        hdPath: hdPathString,
      });

      keyring
        .getAccounts()
        .then((addresses) => {
          assert.notEqual(addresses[0], firstAcct);
          return keyring.serialize();
        })
        .then((serialized) => {
          assert.equal(serialized.hdPath, hdPathString);
          done();
        })
        .catch((reason) => {
          console.log('failed because', reason);
        });
    });

    it('hdPath.Legacy', function (done) {
      const hdPathLegacy = "m/44'/60'/0'";
      keyring.deserialize({
        mnemonic: sampleMnemonic,
        activeIndexes: [0, 1],
        hdPath: hdPathLegacy,
      });

      keyring.getAccounts().then((addersses) => {
        assert.deepEqual(addersses, [
          '0x5a5a19b534db50801fb6dec48ea262ca3a0efda6',
          '0x6729dd439a96d4a7bc6362c231d6931cfaa31088',
        ]);
        done();
      });
    });

    it('hdPath.LedgerLive', function (done) {
      const hdPathLedgerLive = "m/44'/60'/0'/0/0";
      keyring.deserialize({
        mnemonic: sampleMnemonic,
        activeIndexes: [0, 1],
        hdPath: hdPathLedgerLive,
      });

      keyring.getAccounts().then((addersses) => {
        assert.deepEqual(addersses, [
          firstAcct,
          '0x0827a0c8f451b8fcca2cd4e9c23c47a92ca69a56',
        ]);
        done();
      });
    });

    it('hdPath.bip44', function (done) {
      const hdPathBIP44 = "m/44'/60'/0'/0";
      keyring.deserialize({
        mnemonic: sampleMnemonic,
        activeIndexes: [0, 1],
        hdPath: hdPathBIP44,
      });

      keyring.getAccounts().then((addersses) => {
        assert.deepEqual(addersses, [firstAcct, secondAcct]);
        done();
      });
    });

    it('setHdPath', function (done) {
      const hdPathLedgerLive = "m/44'/60'/0'/0/0";
      const hdPathBIP44 = "m/44'/60'/0'/0";

      keyring.deserialize({
        mnemonic: sampleMnemonic,
        activeIndexes: [0, 1],
        hdPath: hdPathBIP44,
      });
      keyring.setHdPath(hdPathLedgerLive);
      keyring.activeAccounts([1]);

      keyring.getAccounts().then((addersses) => {
        assert.deepEqual(addersses, [
          firstAcct,
          secondAcct,
          '0x0827a0c8f451b8fcca2cd4e9c23c47a92ca69a56',
        ]);
        done();
      });
    });
  });

  /*
  describe('create and restore 1k accounts', function () {
    it('should restore same accounts with no problem', async function () {
      this.timeout(20000)

      for (let i = 0; i < 1e3; i++) {

        keyring = new HdKeyring({
          numberOfAccounts: 1,
        })
        const originalAccounts = await keyring.getAccounts()
        const serialized = await keyring.serialize()
        const mnemonic = serialized.mnemonic

        keyring = new HdKeyring({
          numberOfAccounts: 1,
          mnemonic,
        })
        const restoredAccounts = await keyring.getAccounts()

        const first = originalAccounts[0]
        const restored = restoredAccounts[0]
        const msg = `Should restore same account from mnemonic: "${mnemonic}"`
        assert.equal(restoredAccounts[0], originalAccounts[0], msg)

      }

      return true
    })
  })
  */

  describe('getAppKeyAddress', function () {
    it('should return a public address custom to the provided app key origin', async function () {
      const address = firstAcct;

      keyring = new HdKeyring({
        mnemonic: sampleMnemonic,
        activeIndexes: [0],
      });
      const appKeyAddress = await keyring.getAppKeyAddress(
        address,
        'someapp.origin.io',
      );

      assert.notEqual(address, appKeyAddress);
      assert(ethUtil.isValidAddress(appKeyAddress));

      const accounts = await keyring.getAccounts();
      assert.equal(accounts[0], firstAcct);
    });

    it('should return different addresses when provided different app key origins', async function () {
      keyring = new HdKeyring({
        mnemonic: sampleMnemonic,
        activeIndexes: [0],
      });

      const address = firstAcct;

      const appKeyAddress1 = await keyring.getAppKeyAddress(
        address,
        'someapp.origin.io',
      );

      assert(ethUtil.isValidAddress(appKeyAddress1));

      const appKeyAddress2 = await keyring.getAppKeyAddress(
        address,
        'anotherapp.origin.io',
      );

      assert(ethUtil.isValidAddress(appKeyAddress2));

      assert.notEqual(appKeyAddress1, appKeyAddress2);
    });

    it('should return the same address when called multiple times with the same params', async function () {
      keyring = new HdKeyring({
        mnemonic: sampleMnemonic,
        activeIndexes: [0],
      });

      const address = firstAcct;

      const appKeyAddress1 = await keyring.getAppKeyAddress(
        address,
        'someapp.origin.io',
      );

      assert(ethUtil.isValidAddress(appKeyAddress1));

      const appKeyAddress2 = await keyring.getAppKeyAddress(
        address,
        'someapp.origin.io',
      );

      assert(ethUtil.isValidAddress(appKeyAddress2));

      assert.equal(appKeyAddress1, appKeyAddress2);
    });
  });

  describe('signing methods withAppKeyOrigin option', function () {
    it('should signPersonalMessage with the expected key when passed a withAppKeyOrigin', function (done) {
      const address = firstAcct;
      const message = '0x68656c6c6f20776f726c64';

      const privateKey = Buffer.from(
        '8e82d2d74c50e5c8460f771d38a560ebe1151a9134c65a7e92b28ad0cfae7151',
        'hex',
      );
      const expectedSig = personalSign({ privateKey, data: message });

      keyring.deserialize({
        mnemonic: sampleMnemonic,
        activeIndexes: [0],
      });

      keyring
        .signPersonalMessage(address, message, {
          withAppKeyOrigin: 'someapp.origin.io',
        })
        .then((sig) => {
          assert.equal(sig, expectedSig, 'signed with app key');
          done();
        })
        .catch((reason) => {
          assert(!reason, reason.message);
          done();
        });
    });

    it('should signTypedData with the expected key when passed a withAppKeyOrigin', function (done) {
      const address = firstAcct;
      const typedData = {
        types: {
          EIP712Domain: [],
        },
        domain: {},
        primaryType: 'EIP712Domain',
        message: {},
      };

      const privateKey = Buffer.from(
        '8e82d2d74c50e5c8460f771d38a560ebe1151a9134c65a7e92b28ad0cfae7151',
        'hex',
      );
      const expectedSig = signTypedData({
        privateKey,
        data: typedData,
        version: SignTypedDataVersion.V3,
      });

      keyring.deserialize({
        mnemonic: sampleMnemonic,
        activeIndexes: [0],
      });

      keyring
        .signTypedData_v3(address, typedData, {
          withAppKeyOrigin: 'someapp.origin.io',
        })
        .then((sig) => {
          assert.equal(sig, expectedSig, 'signed with app key');
          done();
        })
        .catch((reason) => {
          assert(!reason, reason.message);
          done();
        });
    });
  });

  describe('removeAccount', function () {
    it('should return correct activeIndexes', async function () {
      const address = firstAcct;

      keyring = new HdKeyring({
        mnemonic: sampleMnemonic,
        activeIndexes: [0, 2, 3, 6],
      });
      await keyring.removeAccount(address);
      const { activeIndexes } = await keyring.serialize();

      assert.equal(activeIndexes.length, 3);
      assert.deepEqual(activeIndexes, [2, 3, 6]);
    });
  });

  describe('accountDetails', function () {
    it('should return correct account details', async function () {
      const address = firstAcct;

      keyring = new HdKeyring({
        mnemonic: sampleMnemonic,
        activeIndexes: [0, 2, 3, 6],
      });

      const accountDetail = await keyring.getAccountDetail(address);

      assert.deepEqual(accountDetail, {
        hdPath: "m/44'/60'/0'/0",
        hdPathType: 'BIP44',
        index: 0,
      });
    });
  });

  describe('passphrase', function () {
    it('should be able to set a passphrase', async function () {
      await keyring.deserialize({
        mnemonic: sampleMnemonic,
      });
      keyring.setPassphrase('abc123');
      keyring.activeAccounts([0, 1]);
      const result = await keyring.getAccounts();

      assert.deepEqual(result, [
        '0x8db9506aa1c0e2c07dc03417ded629e0cffe2412',
        '0x805eacc9c707b94581fd2a230f437bd370fe229c',
      ]);
    });

    it('needPassphrase', async function () {
      keyring = new HdKeyring({
        mnemonic: sampleMnemonic,
        needPassphrase: true,
        accounts: [
          '0x8db9506aa1c0e2c07dc03417ded629e0cffe2412',
          '0x805eacc9c707b94581fd2a230f437bd370fe229c',
        ],
      });

      assert.equal(keyring.wallets.length, 0);
      assert.equal(keyring.accounts.length, 2);
    });

    it('get wallet when set passphrase', async function () {
      await keyring.deserialize({
        mnemonic: sampleMnemonic,
        needPassphrase: true,
        accounts: [
          '0x8db9506aa1c0e2c07dc03417ded629e0cffe2412',
          '0x805eacc9c707b94581fd2a230f437bd370fe229c',
        ],
        accountDetails: {
          '0x8db9506aa1c0e2c07dc03417ded629e0cffe2412': {
            hdPath: "m/44'/60'/0'/0",
            hdPathType: 'BIP44',
            index: 0,
          },
          '0x805eacc9c707b94581fd2a230f437bd370fe229c': {
            hdPath: "m/44'/60'/0'/0",
            hdPathType: 'BIP44',
            index: 1,
          },
          [firstAcct]: {
            hdPath: "m/44'/60'/0'/0",
            hdPathType: 'BIP44',
            index: 0,
          },
        },
      });

      assert.equal(keyring.wallets.length, 0);

      keyring.setPassphrase('abc123');

      assert.equal(keyring.wallets.length, 2);
    });
  });
});
