var __create = Object.create;
var __defProp = Object.defineProperty;
var __defProps = Object.defineProperties;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropDescs = Object.getOwnPropertyDescriptors;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getOwnPropSymbols = Object.getOwnPropertySymbols;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __propIsEnum = Object.prototype.propertyIsEnumerable;
var __defNormalProp = (obj, key, value) => key in obj ? __defProp(obj, key, { enumerable: true, configurable: true, writable: true, value }) : obj[key] = value;
var __spreadValues = (a, b) => {
  for (var prop in b || (b = {}))
    if (__hasOwnProp.call(b, prop))
      __defNormalProp(a, prop, b[prop]);
  if (__getOwnPropSymbols)
    for (var prop of __getOwnPropSymbols(b)) {
      if (__propIsEnum.call(b, prop))
        __defNormalProp(a, prop, b[prop]);
    }
  return a;
};
var __spreadProps = (a, b) => __defProps(a, __getOwnPropDescs(b));
var __commonJS = (cb, mod) => function __require() {
  return mod || (0, cb[__getOwnPropNames(cb)[0]])((mod = { exports: {} }).exports, mod), mod.exports;
};
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var __publicField = (obj, key, value) => __defNormalProp(obj, typeof key !== "symbol" ? key + "" : key, value);
var __async = (__this, __arguments, generator) => {
  return new Promise((resolve, reject) => {
    var fulfilled = (value) => {
      try {
        step(generator.next(value));
      } catch (e) {
        reject(e);
      }
    };
    var rejected = (value) => {
      try {
        step(generator.throw(value));
      } catch (e) {
        reject(e);
      }
    };
    var step = (x) => x.done ? resolve(x.value) : Promise.resolve(x.value).then(fulfilled, rejected);
    step((generator = generator.apply(__this, __arguments)).next());
  });
};

// node_modules/slip39/src/slip39_helper.js
var require_slip39_helper = __commonJS({
  "node_modules/slip39/src/slip39_helper.js"(exports2, module2) {
    var crypto;
    try {
      crypto = require("crypto");
    } catch (err) {
      throw new Error("crypto support must be enabled");
    }
    var RADIX_BITS = 10;
    var ID_BITS_LENGTH = 15;
    var ITERATION_EXP_BITS_LENGTH = 4;
    var EXTENDABLE_BACKUP_FLAG_BITS_LENGTH = 1;
    var ITERATION_EXP_WORDS_LENGTH = parseInt(
      (ID_BITS_LENGTH + EXTENDABLE_BACKUP_FLAG_BITS_LENGTH + ITERATION_EXP_BITS_LENGTH + RADIX_BITS - 1) / RADIX_BITS,
      10
    );
    var MAX_ITERATION_EXP = Math.pow(2, ITERATION_EXP_BITS_LENGTH);
    var MAX_SHARE_COUNT = 16;
    var CHECKSUM_WORDS_LENGTH = 3;
    var DIGEST_LENGTH = 4;
    var CUSTOMIZATION_STRING_NON_EXTENDABLE = "shamir";
    var CUSTOMIZATION_STRING_EXTENDABLE = "shamir_extendable";
    var MIN_ENTROPY_BITS = 128;
    var METADATA_WORDS_LENGTH = ITERATION_EXP_WORDS_LENGTH + 2 + CHECKSUM_WORDS_LENGTH;
    var MNEMONICS_WORDS_LENGTH = parseInt(
      METADATA_WORDS_LENGTH + (MIN_ENTROPY_BITS + RADIX_BITS - 1) / RADIX_BITS,
      10
    );
    var ITERATION_COUNT = 1e4;
    var ROUND_COUNT = 4;
    var DIGEST_INDEX = 254;
    var SECRET_INDEX = 255;
    var slip39EncodeHex = function(str) {
      let bytes = [];
      for (let i = 0; i < str.length; ++i) {
        bytes.push(str.charCodeAt(i));
      }
      return bytes;
    };
    var slip39Generate = function(m, v = (_) => _) {
      let n = m;
      const arr = [];
      for (let i = 0; i < n; i++) {
        arr[i] = v(i);
      }
      return arr;
    };
    var BIGINT_WORD_BITS = BigInt(8);
    function decodeBigInt(bytes) {
      let result = BigInt(0);
      for (let i = 0; i < bytes.length; i++) {
        let b = BigInt(bytes[bytes.length - i - 1]);
        result = result + (b << BIGINT_WORD_BITS * BigInt(i));
      }
      return result;
    }
    function encodeBigInt(number, paddedLength = 0) {
      let num = number;
      const BYTE_MASK = BigInt(255);
      const BIGINT_ZERO = BigInt(0);
      let result = new Array(0);
      while (num > BIGINT_ZERO) {
        let i = parseInt(num & BYTE_MASK, 10);
        result.unshift(i);
        num = num >> BIGINT_WORD_BITS;
      }
      for (let i = result.length; i < paddedLength; i++) {
        result.unshift(0);
      }
      if (paddedLength !== 0 && result.length > paddedLength) {
        throw new Error(
          `Error in encoding BigInt value, expected less than ${paddedLength} length value, got ${result.length}`
        );
      }
      return result;
    }
    function bitsToBytes(n) {
      const res = (n + 7) / 8;
      const b = parseInt(res, RADIX_BITS);
      return b;
    }
    function bitsToWords(n) {
      const res = (n + RADIX_BITS - 1) / RADIX_BITS;
      const b = parseInt(res, RADIX_BITS);
      return b;
    }
    function randomBytes(length = 32) {
      let randoms = crypto.randomBytes(length);
      return Array.prototype.slice.call(randoms, 0);
    }
    function roundFunction(round, passphrase, exp, salt, secret) {
      const saltedSecret = salt.concat(secret);
      const roundedPhrase = [round].concat(passphrase);
      const count = (ITERATION_COUNT << exp) / ROUND_COUNT;
      const key = crypto.pbkdf2Sync(
        Buffer.from(roundedPhrase),
        Buffer.from(saltedSecret),
        count,
        secret.length,
        "sha256"
      );
      return Array.prototype.slice.call(key, 0);
    }
    function crypt(masterSecret, passphrase, iterationExponent, identifier, extendableBackupFlag, encrypt = true) {
      if (iterationExponent < 0 || iterationExponent > MAX_ITERATION_EXP) {
        throw Error(
          `Invalid iteration exponent (${iterationExponent}). Expected between 0 and ${MAX_ITERATION_EXP}`
        );
      }
      let IL = masterSecret.slice().slice(0, masterSecret.length / 2);
      let IR = masterSecret.slice().slice(masterSecret.length / 2);
      const pwd = slip39EncodeHex(passphrase);
      const salt = getSalt(identifier, extendableBackupFlag);
      let range = slip39Generate(ROUND_COUNT);
      range = encrypt ? range : range.reverse();
      range.forEach((round) => {
        const f = roundFunction(round, pwd, iterationExponent, salt, IR);
        const t = xor(IL, f);
        IL = IR;
        IR = t;
      });
      return IR.concat(IL);
    }
    function createDigest(randomData, sharedSecret) {
      const hmac = crypto.createHmac("sha256", Buffer.from(randomData));
      hmac.update(Buffer.from(sharedSecret));
      let result = hmac.digest();
      result = result.slice(0, 4);
      return Array.prototype.slice.call(result, 0);
    }
    function splitSecret(threshold, shareCount, sharedSecret) {
      if (threshold <= 0) {
        throw Error(
          `The requested threshold (${threshold}) must be a positive integer.`
        );
      }
      if (threshold > shareCount) {
        throw Error(
          `The requested threshold (${threshold}) must not exceed the number of shares (${shareCount}).`
        );
      }
      if (shareCount > MAX_SHARE_COUNT) {
        throw Error(
          `The requested number of shares (${shareCount}) must not exceed ${MAX_SHARE_COUNT}.`
        );
      }
      if (threshold === 1) {
        return slip39Generate(shareCount, () => sharedSecret);
      }
      const randomShareCount = threshold - 2;
      const randomPart = randomBytes(sharedSecret.length - DIGEST_LENGTH);
      const digest = createDigest(randomPart, sharedSecret);
      let baseShares = /* @__PURE__ */ new Map();
      let shares = [];
      if (randomShareCount) {
        shares = slip39Generate(
          randomShareCount,
          () => randomBytes(sharedSecret.length)
        );
        shares.forEach((item, idx) => {
          baseShares.set(idx, item);
        });
      }
      baseShares.set(DIGEST_INDEX, digest.concat(randomPart));
      baseShares.set(SECRET_INDEX, sharedSecret);
      for (let i = randomShareCount; i < shareCount; i++) {
        const rr = interpolate(baseShares, i);
        shares.push(rr);
      }
      return shares;
    }
    function generateIdentifier() {
      const byte = bitsToBytes(ID_BITS_LENGTH);
      const bits = ID_BITS_LENGTH % 8;
      const identifier = randomBytes(byte);
      identifier[0] = identifier[0] & (1 << bits) - 1;
      return identifier;
    }
    function xor(a, b) {
      if (a.length !== b.length) {
        throw new Error(
          `Invalid padding in mnemonic or insufficient length of mnemonics (${a.length} or ${b.length})`
        );
      }
      return slip39Generate(a.length, (i) => a[i] ^ b[i]);
    }
    function getSalt(identifier, extendableBackupFlag) {
      if (extendableBackupFlag) {
        return [];
      } else {
        const salt = slip39EncodeHex(CUSTOMIZATION_STRING_NON_EXTENDABLE);
        return salt.concat(identifier);
      }
    }
    function interpolate(shares, x) {
      let xCoord = new Set(shares.keys());
      let arr = Array.from(shares.values(), (v) => v.length);
      let sharesValueLengths = new Set(arr);
      if (sharesValueLengths.size !== 1) {
        throw new Error(
          "Invalid set of shares. All share values must have the same length."
        );
      }
      if (xCoord.has(x)) {
        shares.forEach((v, k) => {
          if (k === x) {
            return v;
          }
        });
      }
      let logProd = 0;
      shares.forEach((v, k) => {
        logProd = logProd + LOG_TABLE[k ^ x];
      });
      let results = slip39Generate(
        sharesValueLengths.values().next().value,
        () => 0
      );
      shares.forEach((v, k) => {
        let sum = 0;
        shares.forEach((vv, kk) => {
          sum = sum + LOG_TABLE[k ^ kk];
        });
        const basis = (logProd - LOG_TABLE[k ^ x] - sum) % 255;
        const logBasisEval = basis < 0 ? 255 + basis : basis;
        v.forEach((item, idx) => {
          const shareVal = item;
          const intermediateSum = results[idx];
          const r = shareVal !== 0 ? EXP_TABLE[(LOG_TABLE[shareVal] + logBasisEval) % 255] : 0;
          const res = intermediateSum ^ r;
          results[idx] = res;
        });
      });
      return results;
    }
    function rs1024Polymod(data) {
      const GEN = [
        14737472,
        29474944,
        58949888,
        117899776,
        235798537,
        470557714,
        940076068,
        814808136,
        565311632,
        66318624
      ];
      let chk = 1;
      data.forEach((byte) => {
        const b = chk >> 20;
        chk = (chk & 1048575) << 10 ^ byte;
        for (let i = 0; i < 10; i++) {
          let gen = (b >> i & 1) !== 0 ? GEN[i] : 0;
          chk = chk ^ gen;
        }
      });
      return chk;
    }
    function get_customization_string(extendableBackupFlag) {
      return extendableBackupFlag ? CUSTOMIZATION_STRING_EXTENDABLE : CUSTOMIZATION_STRING_NON_EXTENDABLE;
    }
    function rs1024CreateChecksum(data, extendableBackupFlag) {
      const values = slip39EncodeHex(get_customization_string(extendableBackupFlag)).concat(data).concat(slip39Generate(CHECKSUM_WORDS_LENGTH, () => 0));
      const polymod = rs1024Polymod(values) ^ 1;
      const result = Array().slip39Generate(CHECKSUM_WORDS_LENGTH, (i) => polymod >> 10 * i & 1023).reverse();
      return result;
    }
    function rs1024VerifyChecksum(data, extendableBackupFlag) {
      return rs1024Polymod(
        slip39EncodeHex(get_customization_string(extendableBackupFlag)).concat(data)
      ) === 1;
    }
    function intFromIndices(indices) {
      let value = BigInt(0);
      const radix = BigInt(Math.pow(2, RADIX_BITS));
      indices.forEach((index) => {
        value = value * radix + BigInt(index);
      });
      return value;
    }
    function intToIndices(value, length, bits) {
      const mask = BigInt((1 << bits) - 1);
      const result = slip39Generate(
        length,
        (i) => parseInt(value >> BigInt(i) * BigInt(bits) & mask, 10)
      );
      return result.reverse();
    }
    function mnemonicFromIndices(indices) {
      const result = indices.map((index) => {
        return WORD_LIST[index];
      });
      return result.toString().split(",").join(" ");
    }
    function mnemonicToIndices(mnemonic) {
      if (typeof mnemonic !== "string") {
        throw new Error(
          `Mnemonic expected to be typeof string with white space separated words. Instead found typeof ${typeof mnemonic}.`
        );
      }
      const words = mnemonic.toLowerCase().split(" ");
      const result = words.reduce((prev, item) => {
        const index = WORD_LIST_MAP[item];
        if (typeof index === "undefined") {
          throw new Error(`Invalid mnemonic word ${item}.`);
        }
        return prev.concat(index);
      }, []);
      return result;
    }
    function recoverSecret(threshold, shares) {
      if (threshold === 1) {
        return shares.values().next().value;
      }
      const sharedSecret = interpolate(shares, SECRET_INDEX);
      const digestShare = interpolate(shares, DIGEST_INDEX);
      const digest = digestShare.slice(0, DIGEST_LENGTH);
      const randomPart = digestShare.slice(DIGEST_LENGTH);
      const recoveredDigest = createDigest(randomPart, sharedSecret);
      if (!listsAreEqual(digest, recoveredDigest)) {
        throw new Error("Invalid digest of the shared secret.");
      }
      return sharedSecret;
    }
    function combineMnemonics(mnemonics, passphrase = "") {
      if (mnemonics === null || mnemonics.length === 0) {
        throw new Error("The list of mnemonics is empty.");
      }
      const decoded = decodeMnemonics(mnemonics);
      const identifier = decoded.identifier;
      const extendableBackupFlag = decoded.extendableBackupFlag;
      const iterationExponent = decoded.iterationExponent;
      const groupThreshold = decoded.groupThreshold;
      const groupCount = decoded.groupCount;
      const groups = decoded.groups;
      if (groups.size < groupThreshold) {
        throw new Error(
          `Insufficient number of mnemonic groups (${groups.size}). The required number of groups is ${groupThreshold}.`
        );
      }
      if (groups.size !== groupThreshold) {
        throw new Error(
          `Wrong number of mnemonic groups. Expected ${groupThreshold} groups, but ${groups.size} were provided.`
        );
      }
      let allShares = /* @__PURE__ */ new Map();
      groups.forEach((members, groupIndex) => {
        const threshold = members.keys().next().value;
        const shares = members.values().next().value;
        if (shares.size !== threshold) {
          const prefix = groupPrefix(
            identifier,
            extendableBackupFlag,
            iterationExponent,
            groupIndex,
            groupThreshold,
            groupCount
          );
          throw new Error(
            `Wrong number of mnemonics. Expected ${threshold} mnemonics starting with "${mnemonicFromIndices(prefix)}", 
 but ${shares.size} were provided.`
          );
        }
        const recovered = recoverSecret(threshold, shares);
        allShares.set(groupIndex, recovered);
      });
      const ems = recoverSecret(groupThreshold, allShares);
      const id = intToIndices(BigInt(identifier), ITERATION_EXP_WORDS_LENGTH, 8);
      const ms = crypt(
        ems,
        passphrase,
        iterationExponent,
        id,
        extendableBackupFlag,
        false
      );
      return ms;
    }
    function decodeMnemonics(mnemonics) {
      if (!(mnemonics instanceof Array)) {
        throw new Error("Mnemonics should be an array of strings");
      }
      const identifiers = /* @__PURE__ */ new Set();
      const extendableBackupFlags = /* @__PURE__ */ new Set();
      const iterationExponents = /* @__PURE__ */ new Set();
      const groupThresholds = /* @__PURE__ */ new Set();
      const groupCounts = /* @__PURE__ */ new Set();
      const groups = /* @__PURE__ */ new Map();
      mnemonics.forEach((mnemonic) => {
        const decoded = decodeMnemonic(mnemonic);
        identifiers.add(decoded.identifier);
        extendableBackupFlags.add(decoded.extendableBackupFlag);
        iterationExponents.add(decoded.iterationExponent);
        const groupIndex = decoded.groupIndex;
        groupThresholds.add(decoded.groupThreshold);
        groupCounts.add(decoded.groupCount);
        const memberIndex = decoded.memberIndex;
        const memberThreshold = decoded.memberThreshold;
        const share = decoded.share;
        const group = !groups.has(groupIndex) ? /* @__PURE__ */ new Map() : groups.get(groupIndex);
        const member = !group.has(memberThreshold) ? /* @__PURE__ */ new Map() : group.get(memberThreshold);
        member.set(memberIndex, share);
        group.set(memberThreshold, member);
        if (group.size !== 1) {
          throw new Error(
            "Invalid set of mnemonics. All mnemonics in a group must have the same member threshold."
          );
        }
        groups.set(groupIndex, group);
      });
      if (identifiers.size !== 1 || extendableBackupFlags.size !== 1 || iterationExponents.size !== 1) {
        throw new Error(
          `Invalid set of mnemonics. All mnemonics must begin with the same ${ITERATION_EXP_WORDS_LENGTH} words.`
        );
      }
      if (groupThresholds.size !== 1) {
        throw new Error(
          "Invalid set of mnemonics. All mnemonics must have the same group threshold."
        );
      }
      if (groupCounts.size !== 1) {
        throw new Error(
          "Invalid set of mnemonics. All mnemonics must have the same group count."
        );
      }
      return {
        identifier: identifiers.values().next().value,
        extendableBackupFlag: extendableBackupFlags.values().next().value,
        iterationExponent: iterationExponents.values().next().value,
        groupThreshold: groupThresholds.values().next().value,
        groupCount: groupCounts.values().next().value,
        groups
      };
    }
    function decodeMnemonic(mnemonic) {
      const data = mnemonicToIndices(mnemonic);
      if (data.length < MNEMONICS_WORDS_LENGTH) {
        throw new Error(
          `Invalid mnemonic length. The length of each mnemonic must be at least ${MNEMONICS_WORDS_LENGTH} words.`
        );
      }
      const paddingLen = RADIX_BITS * (data.length - METADATA_WORDS_LENGTH) % 16;
      if (paddingLen > 8) {
        throw new Error("Invalid mnemonic length.");
      }
      const idExpExtInt = parseInt(
        intFromIndices(data.slice(0, ITERATION_EXP_WORDS_LENGTH)),
        10
      );
      const identifier = idExpExtInt >> ITERATION_EXP_BITS_LENGTH + EXTENDABLE_BACKUP_FLAG_BITS_LENGTH;
      const extendableBackupFlag = idExpExtInt >> ITERATION_EXP_BITS_LENGTH & (1 << EXTENDABLE_BACKUP_FLAG_BITS_LENGTH) - 1;
      const iterationExponent = idExpExtInt & (1 << ITERATION_EXP_BITS_LENGTH) - 1;
      if (!rs1024VerifyChecksum(data, extendableBackupFlag)) {
        throw new Error("Invalid mnemonic checksum");
      }
      const tmp = intFromIndices(
        data.slice(ITERATION_EXP_WORDS_LENGTH, ITERATION_EXP_WORDS_LENGTH + 2)
      );
      const indices = intToIndices(tmp, 5, 4);
      const groupIndex = indices[0];
      const groupThreshold = indices[1];
      const groupCount = indices[2];
      const memberIndex = indices[3];
      const memberThreshold = indices[4];
      const valueData = data.slice(
        ITERATION_EXP_WORDS_LENGTH + 2,
        data.length - CHECKSUM_WORDS_LENGTH
      );
      if (groupCount < groupThreshold) {
        throw new Error(
          `Invalid mnemonic: ${mnemonic}.
 Group threshold (${groupThreshold}) cannot be greater than group count (${groupCount}).`
        );
      }
      const valueInt = intFromIndices(valueData);
      try {
        const valueByteCount = bitsToBytes(
          RADIX_BITS * valueData.length - paddingLen
        );
        const share = encodeBigInt(valueInt, valueByteCount);
        return {
          identifier,
          extendableBackupFlag,
          iterationExponent,
          groupIndex,
          groupThreshold: groupThreshold + 1,
          groupCount: groupCount + 1,
          memberIndex,
          memberThreshold: memberThreshold + 1,
          share
        };
      } catch (e) {
        throw new Error(`Invalid mnemonic padding (${e})`);
      }
    }
    function validateMnemonic2(mnemonic) {
      try {
        decodeMnemonic(mnemonic);
        return true;
      } catch (error) {
        return false;
      }
    }
    function groupPrefix(identifier, extendableBackupFlag, iterationExponent, groupIndex, groupThreshold, groupCount) {
      const idExpInt = BigInt(
        (identifier << ITERATION_EXP_BITS_LENGTH + EXTENDABLE_BACKUP_FLAG_BITS_LENGTH) + (extendableBackupFlag << ITERATION_EXP_BITS_LENGTH) + iterationExponent
      );
      const indc = intToIndices(idExpInt, ITERATION_EXP_WORDS_LENGTH, RADIX_BITS);
      const indc2 = (groupIndex << 6) + (groupThreshold - 1 << 2) + (groupCount - 1 >> 2);
      indc.push(indc2);
      return indc;
    }
    function listsAreEqual(a, b) {
      if (a === null || b === null || a.length !== b.length) {
        return false;
      }
      let i = 0;
      return a.every((item) => {
        return b[i++] === item;
      });
    }
    function encodeMnemonic(identifier, extendableBackupFlag, iterationExponent, groupIndex, groupThreshold, groupCount, memberIndex, memberThreshold, value) {
      const valueWordCount = bitsToWords(value.length * 8);
      const valueInt = decodeBigInt(value);
      let newIdentifier = parseInt(decodeBigInt(identifier), 10);
      const gp = groupPrefix(
        newIdentifier,
        extendableBackupFlag,
        iterationExponent,
        groupIndex,
        groupThreshold,
        groupCount
      );
      const tp = intToIndices(valueInt, valueWordCount, RADIX_BITS);
      const calc = ((groupCount - 1 & 3) << 8) + (memberIndex << 4) + (memberThreshold - 1);
      gp.push(calc);
      const shareData = gp.concat(tp);
      const checksum = rs1024CreateChecksum(shareData, extendableBackupFlag);
      return mnemonicFromIndices(shareData.concat(checksum));
    }
    var EXP_TABLE = [
      1,
      3,
      5,
      15,
      17,
      51,
      85,
      255,
      26,
      46,
      114,
      150,
      161,
      248,
      19,
      53,
      95,
      225,
      56,
      72,
      216,
      115,
      149,
      164,
      247,
      2,
      6,
      10,
      30,
      34,
      102,
      170,
      229,
      52,
      92,
      228,
      55,
      89,
      235,
      38,
      106,
      190,
      217,
      112,
      144,
      171,
      230,
      49,
      83,
      245,
      4,
      12,
      20,
      60,
      68,
      204,
      79,
      209,
      104,
      184,
      211,
      110,
      178,
      205,
      76,
      212,
      103,
      169,
      224,
      59,
      77,
      215,
      98,
      166,
      241,
      8,
      24,
      40,
      120,
      136,
      131,
      158,
      185,
      208,
      107,
      189,
      220,
      127,
      129,
      152,
      179,
      206,
      73,
      219,
      118,
      154,
      181,
      196,
      87,
      249,
      16,
      48,
      80,
      240,
      11,
      29,
      39,
      105,
      187,
      214,
      97,
      163,
      254,
      25,
      43,
      125,
      135,
      146,
      173,
      236,
      47,
      113,
      147,
      174,
      233,
      32,
      96,
      160,
      251,
      22,
      58,
      78,
      210,
      109,
      183,
      194,
      93,
      231,
      50,
      86,
      250,
      21,
      63,
      65,
      195,
      94,
      226,
      61,
      71,
      201,
      64,
      192,
      91,
      237,
      44,
      116,
      156,
      191,
      218,
      117,
      159,
      186,
      213,
      100,
      172,
      239,
      42,
      126,
      130,
      157,
      188,
      223,
      122,
      142,
      137,
      128,
      155,
      182,
      193,
      88,
      232,
      35,
      101,
      175,
      234,
      37,
      111,
      177,
      200,
      67,
      197,
      84,
      252,
      31,
      33,
      99,
      165,
      244,
      7,
      9,
      27,
      45,
      119,
      153,
      176,
      203,
      70,
      202,
      69,
      207,
      74,
      222,
      121,
      139,
      134,
      145,
      168,
      227,
      62,
      66,
      198,
      81,
      243,
      14,
      18,
      54,
      90,
      238,
      41,
      123,
      141,
      140,
      143,
      138,
      133,
      148,
      167,
      242,
      13,
      23,
      57,
      75,
      221,
      124,
      132,
      151,
      162,
      253,
      28,
      36,
      108,
      180,
      199,
      82,
      246
    ];
    var LOG_TABLE = [
      0,
      0,
      25,
      1,
      50,
      2,
      26,
      198,
      75,
      199,
      27,
      104,
      51,
      238,
      223,
      3,
      100,
      4,
      224,
      14,
      52,
      141,
      129,
      239,
      76,
      113,
      8,
      200,
      248,
      105,
      28,
      193,
      125,
      194,
      29,
      181,
      249,
      185,
      39,
      106,
      77,
      228,
      166,
      114,
      154,
      201,
      9,
      120,
      101,
      47,
      138,
      5,
      33,
      15,
      225,
      36,
      18,
      240,
      130,
      69,
      53,
      147,
      218,
      142,
      150,
      143,
      219,
      189,
      54,
      208,
      206,
      148,
      19,
      92,
      210,
      241,
      64,
      70,
      131,
      56,
      102,
      221,
      253,
      48,
      191,
      6,
      139,
      98,
      179,
      37,
      226,
      152,
      34,
      136,
      145,
      16,
      126,
      110,
      72,
      195,
      163,
      182,
      30,
      66,
      58,
      107,
      40,
      84,
      250,
      133,
      61,
      186,
      43,
      121,
      10,
      21,
      155,
      159,
      94,
      202,
      78,
      212,
      172,
      229,
      243,
      115,
      167,
      87,
      175,
      88,
      168,
      80,
      244,
      234,
      214,
      116,
      79,
      174,
      233,
      213,
      231,
      230,
      173,
      232,
      44,
      215,
      117,
      122,
      235,
      22,
      11,
      245,
      89,
      203,
      95,
      176,
      156,
      169,
      81,
      160,
      127,
      12,
      246,
      111,
      23,
      196,
      73,
      236,
      216,
      67,
      31,
      45,
      164,
      118,
      123,
      183,
      204,
      187,
      62,
      90,
      251,
      96,
      177,
      134,
      59,
      82,
      161,
      108,
      170,
      85,
      41,
      157,
      151,
      178,
      135,
      144,
      97,
      190,
      220,
      252,
      188,
      149,
      207,
      205,
      55,
      63,
      91,
      209,
      83,
      57,
      132,
      60,
      65,
      162,
      109,
      71,
      20,
      42,
      158,
      93,
      86,
      242,
      211,
      171,
      68,
      17,
      146,
      217,
      35,
      32,
      46,
      137,
      180,
      124,
      184,
      38,
      119,
      153,
      227,
      165,
      103,
      74,
      237,
      222,
      197,
      49,
      254,
      24,
      13,
      99,
      140,
      128,
      192,
      247,
      112,
      7
    ];
    var WORD_LIST = [
      "academic",
      "acid",
      "acne",
      "acquire",
      "acrobat",
      "activity",
      "actress",
      "adapt",
      "adequate",
      "adjust",
      "admit",
      "adorn",
      "adult",
      "advance",
      "advocate",
      "afraid",
      "again",
      "agency",
      "agree",
      "aide",
      "aircraft",
      "airline",
      "airport",
      "ajar",
      "alarm",
      "album",
      "alcohol",
      "alien",
      "alive",
      "alpha",
      "already",
      "alto",
      "aluminum",
      "always",
      "amazing",
      "ambition",
      "amount",
      "amuse",
      "analysis",
      "anatomy",
      "ancestor",
      "ancient",
      "angel",
      "angry",
      "animal",
      "answer",
      "antenna",
      "anxiety",
      "apart",
      "aquatic",
      "arcade",
      "arena",
      "argue",
      "armed",
      "artist",
      "artwork",
      "aspect",
      "auction",
      "august",
      "aunt",
      "average",
      "aviation",
      "avoid",
      "award",
      "away",
      "axis",
      "axle",
      "beam",
      "beard",
      "beaver",
      "become",
      "bedroom",
      "behavior",
      "being",
      "believe",
      "belong",
      "benefit",
      "best",
      "beyond",
      "bike",
      "biology",
      "birthday",
      "bishop",
      "black",
      "blanket",
      "blessing",
      "blimp",
      "blind",
      "blue",
      "body",
      "bolt",
      "boring",
      "born",
      "both",
      "boundary",
      "bracelet",
      "branch",
      "brave",
      "breathe",
      "briefing",
      "broken",
      "brother",
      "browser",
      "bucket",
      "budget",
      "building",
      "bulb",
      "bulge",
      "bumpy",
      "bundle",
      "burden",
      "burning",
      "busy",
      "buyer",
      "cage",
      "calcium",
      "camera",
      "campus",
      "canyon",
      "capacity",
      "capital",
      "capture",
      "carbon",
      "cards",
      "careful",
      "cargo",
      "carpet",
      "carve",
      "category",
      "cause",
      "ceiling",
      "center",
      "ceramic",
      "champion",
      "change",
      "charity",
      "check",
      "chemical",
      "chest",
      "chew",
      "chubby",
      "cinema",
      "civil",
      "class",
      "clay",
      "cleanup",
      "client",
      "climate",
      "clinic",
      "clock",
      "clogs",
      "closet",
      "clothes",
      "club",
      "cluster",
      "coal",
      "coastal",
      "coding",
      "column",
      "company",
      "corner",
      "costume",
      "counter",
      "course",
      "cover",
      "cowboy",
      "cradle",
      "craft",
      "crazy",
      "credit",
      "cricket",
      "criminal",
      "crisis",
      "critical",
      "crowd",
      "crucial",
      "crunch",
      "crush",
      "crystal",
      "cubic",
      "cultural",
      "curious",
      "curly",
      "custody",
      "cylinder",
      "daisy",
      "damage",
      "dance",
      "darkness",
      "database",
      "daughter",
      "deadline",
      "deal",
      "debris",
      "debut",
      "decent",
      "decision",
      "declare",
      "decorate",
      "decrease",
      "deliver",
      "demand",
      "density",
      "deny",
      "depart",
      "depend",
      "depict",
      "deploy",
      "describe",
      "desert",
      "desire",
      "desktop",
      "destroy",
      "detailed",
      "detect",
      "device",
      "devote",
      "diagnose",
      "dictate",
      "diet",
      "dilemma",
      "diminish",
      "dining",
      "diploma",
      "disaster",
      "discuss",
      "disease",
      "dish",
      "dismiss",
      "display",
      "distance",
      "dive",
      "divorce",
      "document",
      "domain",
      "domestic",
      "dominant",
      "dough",
      "downtown",
      "dragon",
      "dramatic",
      "dream",
      "dress",
      "drift",
      "drink",
      "drove",
      "drug",
      "dryer",
      "duckling",
      "duke",
      "duration",
      "dwarf",
      "dynamic",
      "early",
      "earth",
      "easel",
      "easy",
      "echo",
      "eclipse",
      "ecology",
      "edge",
      "editor",
      "educate",
      "either",
      "elbow",
      "elder",
      "election",
      "elegant",
      "element",
      "elephant",
      "elevator",
      "elite",
      "else",
      "email",
      "emerald",
      "emission",
      "emperor",
      "emphasis",
      "employer",
      "empty",
      "ending",
      "endless",
      "endorse",
      "enemy",
      "energy",
      "enforce",
      "engage",
      "enjoy",
      "enlarge",
      "entrance",
      "envelope",
      "envy",
      "epidemic",
      "episode",
      "equation",
      "equip",
      "eraser",
      "erode",
      "escape",
      "estate",
      "estimate",
      "evaluate",
      "evening",
      "evidence",
      "evil",
      "evoke",
      "exact",
      "example",
      "exceed",
      "exchange",
      "exclude",
      "excuse",
      "execute",
      "exercise",
      "exhaust",
      "exotic",
      "expand",
      "expect",
      "explain",
      "express",
      "extend",
      "extra",
      "eyebrow",
      "facility",
      "fact",
      "failure",
      "faint",
      "fake",
      "false",
      "family",
      "famous",
      "fancy",
      "fangs",
      "fantasy",
      "fatal",
      "fatigue",
      "favorite",
      "fawn",
      "fiber",
      "fiction",
      "filter",
      "finance",
      "findings",
      "finger",
      "firefly",
      "firm",
      "fiscal",
      "fishing",
      "fitness",
      "flame",
      "flash",
      "flavor",
      "flea",
      "flexible",
      "flip",
      "float",
      "floral",
      "fluff",
      "focus",
      "forbid",
      "force",
      "forecast",
      "forget",
      "formal",
      "fortune",
      "forward",
      "founder",
      "fraction",
      "fragment",
      "frequent",
      "freshman",
      "friar",
      "fridge",
      "friendly",
      "frost",
      "froth",
      "frozen",
      "fumes",
      "funding",
      "furl",
      "fused",
      "galaxy",
      "game",
      "garbage",
      "garden",
      "garlic",
      "gasoline",
      "gather",
      "general",
      "genius",
      "genre",
      "genuine",
      "geology",
      "gesture",
      "glad",
      "glance",
      "glasses",
      "glen",
      "glimpse",
      "goat",
      "golden",
      "graduate",
      "grant",
      "grasp",
      "gravity",
      "gray",
      "greatest",
      "grief",
      "grill",
      "grin",
      "grocery",
      "gross",
      "group",
      "grownup",
      "grumpy",
      "guard",
      "guest",
      "guilt",
      "guitar",
      "gums",
      "hairy",
      "hamster",
      "hand",
      "hanger",
      "harvest",
      "have",
      "havoc",
      "hawk",
      "hazard",
      "headset",
      "health",
      "hearing",
      "heat",
      "helpful",
      "herald",
      "herd",
      "hesitate",
      "hobo",
      "holiday",
      "holy",
      "home",
      "hormone",
      "hospital",
      "hour",
      "huge",
      "human",
      "humidity",
      "hunting",
      "husband",
      "hush",
      "husky",
      "hybrid",
      "idea",
      "identify",
      "idle",
      "image",
      "impact",
      "imply",
      "improve",
      "impulse",
      "include",
      "income",
      "increase",
      "index",
      "indicate",
      "industry",
      "infant",
      "inform",
      "inherit",
      "injury",
      "inmate",
      "insect",
      "inside",
      "install",
      "intend",
      "intimate",
      "invasion",
      "involve",
      "iris",
      "island",
      "isolate",
      "item",
      "ivory",
      "jacket",
      "jerky",
      "jewelry",
      "join",
      "judicial",
      "juice",
      "jump",
      "junction",
      "junior",
      "junk",
      "jury",
      "justice",
      "kernel",
      "keyboard",
      "kidney",
      "kind",
      "kitchen",
      "knife",
      "knit",
      "laden",
      "ladle",
      "ladybug",
      "lair",
      "lamp",
      "language",
      "large",
      "laser",
      "laundry",
      "lawsuit",
      "leader",
      "leaf",
      "learn",
      "leaves",
      "lecture",
      "legal",
      "legend",
      "legs",
      "lend",
      "length",
      "level",
      "liberty",
      "library",
      "license",
      "lift",
      "likely",
      "lilac",
      "lily",
      "lips",
      "liquid",
      "listen",
      "literary",
      "living",
      "lizard",
      "loan",
      "lobe",
      "location",
      "losing",
      "loud",
      "loyalty",
      "luck",
      "lunar",
      "lunch",
      "lungs",
      "luxury",
      "lying",
      "lyrics",
      "machine",
      "magazine",
      "maiden",
      "mailman",
      "main",
      "makeup",
      "making",
      "mama",
      "manager",
      "mandate",
      "mansion",
      "manual",
      "marathon",
      "march",
      "market",
      "marvel",
      "mason",
      "material",
      "math",
      "maximum",
      "mayor",
      "meaning",
      "medal",
      "medical",
      "member",
      "memory",
      "mental",
      "merchant",
      "merit",
      "method",
      "metric",
      "midst",
      "mild",
      "military",
      "mineral",
      "minister",
      "miracle",
      "mixed",
      "mixture",
      "mobile",
      "modern",
      "modify",
      "moisture",
      "moment",
      "morning",
      "mortgage",
      "mother",
      "mountain",
      "mouse",
      "move",
      "much",
      "mule",
      "multiple",
      "muscle",
      "museum",
      "music",
      "mustang",
      "nail",
      "national",
      "necklace",
      "negative",
      "nervous",
      "network",
      "news",
      "nuclear",
      "numb",
      "numerous",
      "nylon",
      "oasis",
      "obesity",
      "object",
      "observe",
      "obtain",
      "ocean",
      "often",
      "olympic",
      "omit",
      "oral",
      "orange",
      "orbit",
      "order",
      "ordinary",
      "organize",
      "ounce",
      "oven",
      "overall",
      "owner",
      "paces",
      "pacific",
      "package",
      "paid",
      "painting",
      "pajamas",
      "pancake",
      "pants",
      "papa",
      "paper",
      "parcel",
      "parking",
      "party",
      "patent",
      "patrol",
      "payment",
      "payroll",
      "peaceful",
      "peanut",
      "peasant",
      "pecan",
      "penalty",
      "pencil",
      "percent",
      "perfect",
      "permit",
      "petition",
      "phantom",
      "pharmacy",
      "photo",
      "phrase",
      "physics",
      "pickup",
      "picture",
      "piece",
      "pile",
      "pink",
      "pipeline",
      "pistol",
      "pitch",
      "plains",
      "plan",
      "plastic",
      "platform",
      "playoff",
      "pleasure",
      "plot",
      "plunge",
      "practice",
      "prayer",
      "preach",
      "predator",
      "pregnant",
      "premium",
      "prepare",
      "presence",
      "prevent",
      "priest",
      "primary",
      "priority",
      "prisoner",
      "privacy",
      "prize",
      "problem",
      "process",
      "profile",
      "program",
      "promise",
      "prospect",
      "provide",
      "prune",
      "public",
      "pulse",
      "pumps",
      "punish",
      "puny",
      "pupal",
      "purchase",
      "purple",
      "python",
      "quantity",
      "quarter",
      "quick",
      "quiet",
      "race",
      "racism",
      "radar",
      "railroad",
      "rainbow",
      "raisin",
      "random",
      "ranked",
      "rapids",
      "raspy",
      "reaction",
      "realize",
      "rebound",
      "rebuild",
      "recall",
      "receiver",
      "recover",
      "regret",
      "regular",
      "reject",
      "relate",
      "remember",
      "remind",
      "remove",
      "render",
      "repair",
      "repeat",
      "replace",
      "require",
      "rescue",
      "research",
      "resident",
      "response",
      "result",
      "retailer",
      "retreat",
      "reunion",
      "revenue",
      "review",
      "reward",
      "rhyme",
      "rhythm",
      "rich",
      "rival",
      "river",
      "robin",
      "rocky",
      "romantic",
      "romp",
      "roster",
      "round",
      "royal",
      "ruin",
      "ruler",
      "rumor",
      "sack",
      "safari",
      "salary",
      "salon",
      "salt",
      "satisfy",
      "satoshi",
      "saver",
      "says",
      "scandal",
      "scared",
      "scatter",
      "scene",
      "scholar",
      "science",
      "scout",
      "scramble",
      "screw",
      "script",
      "scroll",
      "seafood",
      "season",
      "secret",
      "security",
      "segment",
      "senior",
      "shadow",
      "shaft",
      "shame",
      "shaped",
      "sharp",
      "shelter",
      "sheriff",
      "short",
      "should",
      "shrimp",
      "sidewalk",
      "silent",
      "silver",
      "similar",
      "simple",
      "single",
      "sister",
      "skin",
      "skunk",
      "slap",
      "slavery",
      "sled",
      "slice",
      "slim",
      "slow",
      "slush",
      "smart",
      "smear",
      "smell",
      "smirk",
      "smith",
      "smoking",
      "smug",
      "snake",
      "snapshot",
      "sniff",
      "society",
      "software",
      "soldier",
      "solution",
      "soul",
      "source",
      "space",
      "spark",
      "speak",
      "species",
      "spelling",
      "spend",
      "spew",
      "spider",
      "spill",
      "spine",
      "spirit",
      "spit",
      "spray",
      "sprinkle",
      "square",
      "squeeze",
      "stadium",
      "staff",
      "standard",
      "starting",
      "station",
      "stay",
      "steady",
      "step",
      "stick",
      "stilt",
      "story",
      "strategy",
      "strike",
      "style",
      "subject",
      "submit",
      "sugar",
      "suitable",
      "sunlight",
      "superior",
      "surface",
      "surprise",
      "survive",
      "sweater",
      "swimming",
      "swing",
      "switch",
      "symbolic",
      "sympathy",
      "syndrome",
      "system",
      "tackle",
      "tactics",
      "tadpole",
      "talent",
      "task",
      "taste",
      "taught",
      "taxi",
      "teacher",
      "teammate",
      "teaspoon",
      "temple",
      "tenant",
      "tendency",
      "tension",
      "terminal",
      "testify",
      "texture",
      "thank",
      "that",
      "theater",
      "theory",
      "therapy",
      "thorn",
      "threaten",
      "thumb",
      "thunder",
      "ticket",
      "tidy",
      "timber",
      "timely",
      "ting",
      "tofu",
      "together",
      "tolerate",
      "total",
      "toxic",
      "tracks",
      "traffic",
      "training",
      "transfer",
      "trash",
      "traveler",
      "treat",
      "trend",
      "trial",
      "tricycle",
      "trip",
      "triumph",
      "trouble",
      "true",
      "trust",
      "twice",
      "twin",
      "type",
      "typical",
      "ugly",
      "ultimate",
      "umbrella",
      "uncover",
      "undergo",
      "unfair",
      "unfold",
      "unhappy",
      "union",
      "universe",
      "unkind",
      "unknown",
      "unusual",
      "unwrap",
      "upgrade",
      "upstairs",
      "username",
      "usher",
      "usual",
      "valid",
      "valuable",
      "vampire",
      "vanish",
      "various",
      "vegan",
      "velvet",
      "venture",
      "verdict",
      "verify",
      "very",
      "veteran",
      "vexed",
      "victim",
      "video",
      "view",
      "vintage",
      "violence",
      "viral",
      "visitor",
      "visual",
      "vitamins",
      "vocal",
      "voice",
      "volume",
      "voter",
      "voting",
      "walnut",
      "warmth",
      "warn",
      "watch",
      "wavy",
      "wealthy",
      "weapon",
      "webcam",
      "welcome",
      "welfare",
      "western",
      "width",
      "wildlife",
      "window",
      "wine",
      "wireless",
      "wisdom",
      "withdraw",
      "wits",
      "wolf",
      "woman",
      "work",
      "worthy",
      "wrap",
      "wrist",
      "writing",
      "wrote",
      "year",
      "yelp",
      "yield",
      "yoga",
      "zero"
    ];
    var WORD_LIST_MAP = WORD_LIST.reduce((obj, val, idx) => {
      obj[val] = idx;
      return obj;
    }, {});
    exports2 = module2.exports = {
      MIN_ENTROPY_BITS,
      generateIdentifier,
      encodeMnemonic,
      validateMnemonic: validateMnemonic2,
      splitSecret,
      combineMnemonics,
      crypt,
      bitsToBytes,
      WORD_LIST,
      decodeMnemonics,
      decodeMnemonic
    };
  }
});

// node_modules/slip39/src/slip39.js
var require_slip39 = __commonJS({
  "node_modules/slip39/src/slip39.js"(exports2, module2) {
    var slipHelper = require_slip39_helper();
    var MAX_DEPTH = 2;
    var Slip39Node = class {
      constructor(index = 0, description = "", mnemonic = "", children = []) {
        this.index = index;
        this.description = description;
        this.mnemonic = mnemonic;
        this.children = children;
      }
      get mnemonics() {
        if (this.children.length === 0) {
          return [this.mnemonic];
        }
        const result = this.children.reduce((prev, item) => {
          return prev.concat(item.mnemonics);
        }, []);
        return result;
      }
    };
    var _Slip39 = class _Slip39 {
      constructor({
        iterationExponent = 0,
        extendableBackupFlag = 0,
        identifier,
        groupCount,
        groupThreshold
      } = {}) {
        this.iterationExponent = iterationExponent;
        this.extendableBackupFlag = extendableBackupFlag;
        this.identifier = identifier;
        this.groupCount = groupCount;
        this.groupThreshold = groupThreshold;
      }
      static fromArray(masterSecret, {
        passphrase = "",
        threshold = 1,
        groups = [[1, 1, "Default 1-of-1 group share"]],
        iterationExponent = 0,
        extendableBackupFlag = 1,
        title = "My default slip39 shares"
      } = {}) {
        if (masterSecret.length * 8 < slipHelper.MIN_ENTROPY_BITS) {
          throw Error(
            `The length of the master secret (${masterSecret.length} bytes) must be at least ${slipHelper.bitsToBytes(slipHelper.MIN_ENTROPY_BITS)} bytes.`
          );
        }
        if (masterSecret.length % 2 !== 0) {
          throw Error(
            "The length of the master secret in bytes must be an even number."
          );
        }
        if (!/^[\x20-\x7E]*$/.test(passphrase)) {
          throw Error(
            "The passphrase must contain only printable ASCII characters (code points 32-126)."
          );
        }
        if (threshold > groups.length) {
          throw Error(
            `The requested group threshold (${threshold}) must not exceed the number of groups (${groups.length}).`
          );
        }
        groups.forEach((item) => {
          if (item[0] === 1 && item[1] > 1) {
            throw Error(
              `Creating multiple member shares with member threshold 1 is not allowed. Use 1-of-1 member sharing instead. ${groups.join()}`
            );
          }
        });
        const identifier = slipHelper.generateIdentifier();
        const slip = new _Slip39({
          iterationExponent,
          extendableBackupFlag,
          identifier,
          groupCount: groups.length,
          groupThreshold: threshold
        });
        const encryptedMasterSecret = slipHelper.crypt(
          masterSecret,
          passphrase,
          iterationExponent,
          slip.identifier,
          extendableBackupFlag
        );
        const root = slip.buildRecursive(
          new Slip39Node(0, title),
          groups,
          encryptedMasterSecret,
          threshold
        );
        slip.root = root;
        return slip;
      }
      buildRecursive(currentNode, nodes, secret, threshold, index) {
        if (nodes.length === 0) {
          const mnemonic = slipHelper.encodeMnemonic(
            this.identifier,
            this.extendableBackupFlag,
            this.iterationExponent,
            index,
            this.groupThreshold,
            this.groupCount,
            currentNode.index,
            threshold,
            secret
          );
          currentNode.mnemonic = mnemonic;
          return currentNode;
        }
        const secretShares = slipHelper.splitSecret(
          threshold,
          nodes.length,
          secret
        );
        let children = [];
        let idx = 0;
        nodes.forEach((item) => {
          const n = item[0];
          const m = item[1];
          const d = item[2] || "";
          const members = Array().slip39Generate(m, () => [n, 0, d]);
          const node = new Slip39Node(idx, d);
          const branch = this.buildRecursive(
            node,
            members,
            secretShares[idx],
            n,
            currentNode.index
          );
          children = children.concat(branch);
          idx = idx + 1;
        });
        currentNode.children = children;
        return currentNode;
      }
      static recoverSecret(mnemonics, passphrase) {
        return slipHelper.combineMnemonics(mnemonics, passphrase);
      }
      static validateMnemonic(mnemonic) {
        return slipHelper.validateMnemonic(mnemonic);
      }
      fromPath(path) {
        this.validatePath(path);
        const children = this.parseChildren(path);
        if (typeof children === "undefined" || children.length === 0) {
          return this.root;
        }
        return children.reduce((prev, childNumber) => {
          let childrenLen = prev.children.length;
          if (childNumber >= childrenLen) {
            throw new Error(
              `The path index (${childNumber}) exceeds the children index (${childrenLen - 1}).`
            );
          }
          return prev.children[childNumber];
        }, this.root);
      }
      validatePath(path) {
        if (!path.match(/(^r)(\/\d{1,2}){0,2}$/)) {
          throw new Error('Expected valid path e.g. "r/0/0".');
        }
        const depth = path.split("/");
        const pathLength = depth.length - 1;
        if (pathLength > MAX_DEPTH) {
          throw new Error(
            `Path's (${path}) max depth (${MAX_DEPTH}) is exceeded (${pathLength}).`
          );
        }
      }
      parseChildren(path) {
        const splitted = path.split("/").slice(1);
        const result = splitted.map((pathFragment) => {
          return parseInt(pathFragment);
        });
        return result;
      }
    };
    __publicField(_Slip39, "decodeMnemonics", slipHelper.decodeMnemonics);
    __publicField(_Slip39, "decodeMnemonic", slipHelper.decodeMnemonic);
    var Slip39 = _Slip39;
    exports2 = module2.exports = Slip39;
  }
});

// node_modules/slip39/index.js
var require_slip392 = __commonJS({
  "node_modules/slip39/index.js"(exports2, module2) {
    module2.exports = require_slip39();
  }
});

// index.ts
var eth_hd_keyring_exports = {};
__export(eth_hd_keyring_exports, {
  default: () => eth_hd_keyring_default
});
module.exports = __toCommonJS(eth_hd_keyring_exports);
var import_hdkey = require("ethereum-cryptography/hdkey");
var import_eth_simple_keyring = __toESM(require("@rabby-wallet/eth-simple-keyring"));
var bip39 = __toESM(require("@scure/bip39"));
var import_english = require("@scure/bip39/wordlists/english");
var sigUtil = __toESM(require("eth-sig-util"));
var import_util = require("@ethereumjs/util");
var import_slip39 = __toESM(require_slip392());
var type = "HD Key Tree";
var HD_PATH_BASE = {
  ["BIP44" /* BIP44 */]: "m/44'/60'/0'/0",
  ["Legacy" /* Legacy */]: "m/44'/60'/0'",
  ["LedgerLive" /* LedgerLive */]: "m/44'/60'/0'/0/0"
};
var HD_PATH_TYPE = {
  [HD_PATH_BASE["BIP44" /* BIP44 */]]: "BIP44" /* BIP44 */,
  [HD_PATH_BASE["Legacy" /* Legacy */]]: "Legacy" /* Legacy */,
  [HD_PATH_BASE["LedgerLive" /* LedgerLive */]]: "LedgerLive" /* LedgerLive */
};
var _HdKeyring = class _HdKeyring extends import_eth_simple_keyring.default {
  /* PUBLIC METHODS */
  constructor(opts = {}) {
    super();
    this.type = type;
    this.mnemonic = null;
    this.hdPath = HD_PATH_BASE["BIP44" /* BIP44 */];
    this.wallets = [];
    this.activeIndexes = [];
    this.index = 0;
    this.page = 0;
    this.perPage = 5;
    this.byImport = false;
    this.publicKey = "";
    this.needPassphrase = false;
    this.accounts = [];
    this.accountDetails = {};
    this.passphrase = "";
    this.isSlip39 = false;
    this.setAccountDetail = (address, accountDetail) => {
      this.accountDetails = __spreadProps(__spreadValues({}, this.accountDetails), {
        [address.toLowerCase()]: accountDetail
      });
    };
    this.getAccountDetail = (address) => {
      return this.accountDetails[address.toLowerCase()];
    };
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
      isSlip39: this.isSlip39
    });
  }
  deserialize(opts = {}) {
    this.wallets = [];
    this.mnemonic = null;
    this.hdPath = opts.hdPath || HD_PATH_BASE["BIP44" /* BIP44 */];
    this.byImport = !!opts.byImport;
    this.index = opts.index || 0;
    this.needPassphrase = opts.needPassphrase || !!opts.passphrase;
    this.passphrase = opts.passphrase;
    this.accounts = opts.accounts || [];
    this.accountDetails = opts.accountDetails || {};
    this.publicKey = opts.publicKey || "";
    this.isSlip39 = opts.isSlip39 || false;
    if (opts.mnemonic) {
      this.mnemonic = opts.mnemonic;
      this.setPassphrase(opts.passphrase || "");
    }
    if (!this.accounts.length && opts.activeIndexes) {
      return this.activeAccounts(opts.activeIndexes);
    }
    return Promise.resolve([]);
  }
  initFromMnemonic(mnemonic, passphrase) {
    this.mnemonic = mnemonic;
    const seed = this.getSeed(mnemonic, passphrase);
    this.hdWallet = import_hdkey.HDKey.fromMasterSeed(seed);
    if (!this.publicKey) {
      this.publicKey = this.calcBasePublicKey(this.hdWallet);
    }
  }
  calcBasePublicKey(hdKey) {
    return (0, import_util.bytesToHex)(
      hdKey.derive(this.getHDPathBase("BIP44" /* BIP44 */)).publicKey
    );
  }
  addAccounts(numberOfAccounts = 1) {
    if (!this.hdWallet) {
      this.initFromMnemonic(bip39.generateMnemonic(import_english.wordlist));
    }
    let count = numberOfAccounts;
    let currentIdx = 0;
    const addresses = [];
    while (count) {
      const [address, wallet] = this._addressFromIndex(currentIdx);
      if (this.wallets.find(
        (w) => (0, import_util.bytesToHex)(w.publicKey) === (0, import_util.bytesToHex)(wallet.publicKey)
      )) {
        currentIdx++;
      } else {
        this.wallets.push(wallet);
        addresses.push(address);
        this.setAccountDetail(address, {
          hdPath: this.hdPath,
          hdPathType: HD_PATH_TYPE[this.hdPath],
          index: currentIdx
        });
        count--;
      }
      if (!this.accounts.includes(address)) {
        this.accounts.push(address);
      }
    }
    return Promise.resolve(addresses);
  }
  activeAccounts(indexes) {
    const accounts = [];
    for (const index of indexes) {
      const [address, wallet] = this._addressFromIndex(index);
      this.wallets.push(wallet);
      this.activeIndexes.push(index);
      accounts.push(address);
      this.setAccountDetail(address, {
        hdPath: this.hdPath,
        hdPathType: HD_PATH_TYPE[this.hdPath],
        index
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
  getAddresses(start, end) {
    const from = start;
    const to = end;
    const accounts = [];
    for (let i = from; i < to; i++) {
      const [address] = this._addressFromIndex(i);
      accounts.push({
        address,
        index: i + 1
      });
    }
    return accounts;
  }
  removeAccount(address) {
    var _a;
    const index = (_a = this.getInfoByAddress(address)) == null ? void 0 : _a.index;
    this.activeIndexes = this.activeIndexes.filter((i) => i !== index);
    delete this.accountDetails[address];
    this.accounts = this.accounts.filter((acc) => acc !== address);
    this.wallets = this.wallets.filter(
      ({ publicKey }) => sigUtil.normalize(this._addressFromPublicKey(publicKey)).toLowerCase() !== address.toLowerCase()
    );
  }
  __getPage(increment) {
    return __async(this, null, function* () {
      this.page += increment;
      if (!this.page || this.page <= 0) {
        this.page = 1;
      }
      const from = (this.page - 1) * this.perPage;
      const to = from + this.perPage;
      const accounts = [];
      for (let i = from; i < to; i++) {
        const [address] = this._addressFromIndex(i);
        accounts.push({
          address,
          index: i + 1
        });
      }
      return accounts;
    });
  }
  getAccounts() {
    var _a;
    if ((_a = this.accounts) == null ? void 0 : _a.length) {
      return Promise.resolve(this.accounts);
    }
    return Promise.resolve(
      this.wallets.map((w) => {
        return sigUtil.normalize(this._addressFromPublicKey(w.publicKey));
      })
    );
  }
  getInfoByAddress(address) {
    const detail = this.accountDetails[address];
    if (detail) {
      return __spreadProps(__spreadValues({}, detail), {
        basePublicKey: this.publicKey
      });
    }
    for (const key in this.wallets) {
      const wallet = this.wallets[key];
      if (sigUtil.normalize(this._addressFromPublicKey(wallet.publicKey)) === address.toLowerCase()) {
        return {
          index: Number(key),
          hdPathType: HD_PATH_TYPE[this.hdPath],
          hdPath: this.hdPath,
          basePublicKey: this.publicKey
        };
      }
    }
    return null;
  }
  _addressFromIndex(i) {
    const child = this.getChildForIndex(i);
    const wallet = {
      publicKey: (0, import_util.privateToPublic)(child.privateKey),
      privateKey: child.privateKey
    };
    const address = sigUtil.normalize(
      this._addressFromPublicKey(wallet.publicKey)
    );
    return [address, wallet];
  }
  _addressFromPublicKey(publicKey) {
    return (0, import_util.bytesToHex)((0, import_util.publicToAddress)(publicKey, true)).toLowerCase();
  }
  generateMnemonic() {
    return bip39.generateMnemonic(import_english.wordlist);
  }
  setHdPath(hdPath = HD_PATH_BASE["BIP44" /* BIP44 */]) {
    this.hdPath = hdPath;
  }
  getChildForIndex(index) {
    return this.hdWallet.derive(this.getPathForIndex(index));
  }
  isLedgerLiveHdPath() {
    return this.hdPath === HD_PATH_BASE["LedgerLive" /* LedgerLive */];
  }
  getPathForIndex(index) {
    return this.isLedgerLiveHdPath() ? `m/44'/60'/${index}'/0/0` : `${this.hdPath}/${index}`;
  }
  setPassphrase(passphrase) {
    this.passphrase = passphrase;
    this.initFromMnemonic(this.mnemonic, passphrase);
    for (const acc of this.accounts) {
      const detail = this.getAccountDetail(acc);
      if (detail) {
        this.setHdPath(detail.hdPath);
        const [address, wallet] = this._addressFromIndex(detail.index);
        if (address.toLowerCase() === acc.toLowerCase()) {
          this.wallets.push(wallet);
        }
      }
    }
  }
  /**
   * if passphrase is correct, the publicKey will be the same as the stored one
   */
  checkPassphrase(passphrase) {
    const seed = this.getSeed(this.mnemonic, passphrase);
    const hdWallet = import_hdkey.HDKey.fromMasterSeed(seed);
    const publicKey = this.calcBasePublicKey(hdWallet);
    return this.publicKey === publicKey;
  }
  getHDPathBase(hdPathType) {
    return HD_PATH_BASE[hdPathType];
  }
  setHDPathType(hdPathType) {
    return __async(this, null, function* () {
      const hdPath = this.getHDPathBase(hdPathType);
      this.setHdPath(hdPath);
    });
  }
  getSeed(mnemonic, passphrase) {
    if (_HdKeyring.checkMnemonicIsSlip39(mnemonic)) {
      this.isSlip39 = true;
      return this.slip39MnemonicToSeedSync(mnemonic, passphrase);
    }
    return bip39.mnemonicToSeedSync(mnemonic, passphrase);
  }
  slip39MnemonicToSeedSync(mnemonic, passphrase) {
    const secretShares = mnemonic.split("\n");
    const secretBytes = import_slip39.default.recoverSecret(secretShares, passphrase);
    const seed = (0, import_util.hexToBytes)((0, import_util.bytesToHex)(secretBytes));
    return seed;
  }
  static checkMnemonicIsSlip39(mnemonic) {
    const arr = mnemonic.split("\n");
    try {
      _HdKeyring.slip39DecodeMnemonics(arr);
      return true;
    } catch (e) {
      return false;
    }
  }
  static slip39DecodeMnemonics(shares) {
    return import_slip39.default.decodeMnemonics(shares);
  }
  static slip39DecodeMnemonic(share) {
    return import_slip39.default.decodeMnemonic(share);
  }
  static validateMnemonic(mnemonic) {
    if (this.checkMnemonicIsSlip39(mnemonic)) {
      return true;
    }
    return bip39.validateMnemonic(mnemonic, import_english.wordlist);
  }
};
_HdKeyring.type = type;
var HdKeyring = _HdKeyring;
var eth_hd_keyring_default = HdKeyring;
