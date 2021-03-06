/**
 * This is a ChromeWorker script for crypto operations;
 * it's done on a worker so it won't block the main thread.
 */

/**
 * utility functions
 */
function range(max) { for (let i = 0; i < max; i++) yield i; }
function debug(msg, ...rest) {
    postMessage({log: String(msg) + rest.join(", ")});
}

/**
 * ctypes declarations
 */

const ABI = /^Win\d+$/.test(navigator.platform) ?
                ctypes.winapi_abi : ctypes.default_abi;

const KeyType = {
    nullKey: 0,
    rsaKey: 1,
    dsaKey: 2,
    fortezzaKey: 3, /* deprecated */
    dhKey: 4,
    keaKey: 5, /* deprecated */
    ecKey: 6,
    rsaPssKey: 7,
    rsaOaepKey: 8,
}; /* See keythi.h */

const SECItemType = {
    siBuffer: 0,
    siClearDataBuffer: 1,
    siCipherDataBuffer: 2,
    siDERCertBuffer: 3,
    siEncodedCertBuffer: 4,
    siDERNameBuffer: 5,
    siEncodedNameBuffer: 6,
    siAsciiNameString: 7,
    siAsciiString: 8,
    siDEROID: 9,
    siUnsignedInteger: 10,
    siUTCTime: 11,
    siGeneralizedTime: 12,
    siVisibleString: 13,
    siUTF8String: 14,
    siBMPString: 15,
}; /* See seccomon.h */

// mechanisms; see pkcs11t.h
const CK_MECHANISM_TYPE = ctypes.unsigned_long;
const CKM_RSA_PKCS_KEY_PAIR_GEN = 0x00000000;
const CKM_DES_KEY_GEN = 0x00000120;
const CKM_DES3_ECB = 0x00000132;
const CKM_DES3_CBC_PAD = 0x00000136;

// key attributes
const CK_ATTRIBUTE_TYPE = ctypes.unsigned_long;
const CKA_DECRYPT = 0x00000105;
const CKA_WRAP = 0x00000106;
const CKA_UNWRAP = 0x00000107;
const CKA_SIGN = 0x00000108;
const CKA_SIGN_RECOVER = 0x00000109;

const CK_KEY_TYPE = ctypes.unsigned_long;

// enum SECOidTag; see secoidt.h
const SECOidTag = ctypes.int;
const SEC_OID_AES_256_CBC = 188;
const SEC_OID_PKCS1_SHA256_WITH_RSA_ENCRYPTION = 194;
const SEC_OID_PKCS1_SHA384_WITH_RSA_ENCRYPTION = 195;
const SEC_OID_PKCS1_SHA512_WITH_RSA_ENCRYPTION = 196;

const PK11Origin = ctypes.int;
const PK11_OriginUnwrap = 4;

const PK11SlotInfo = ctypes.StructType("PK11SlotInfo");

const SECStatus = ctypes.int;

const SECItem = ctypes.StructType("SECItem", [
    { type: ctypes.int }, // SECItemType
    { data: ctypes.uint8_t.ptr },
    { length: ctypes.unsigned_int },
    ]);
const SECKEYRSAPublicKey = ctypes.StructType("SECKEYRSAPublicKey", [
    { arena: ctypes.voidptr_t }, // PLArenaPool*
    { modulus: SECItem },
    { publicExponent: SECItem },
    ]);
const SECKEYPublicKey = ctypes.StructType("SECKEYPublicKeyStr", [
    { arena: ctypes.voidptr_t }, // PLArenaPool*
    { keyType: ctypes.int }, // KeyType
    { pkcs11Slot: PK11SlotInfo.ptr },
    { pkcs11ID: ctypes.unsigned_long },  // CK_OBJECT_HANDLE
    // XXX Mook this is wrong, but js-ctypes doesn't support unions
    // see mozilla bug 535378
    /*
    union {
        SECKEYRSAPublicKey rsa;
        SECKEYDSAPublicKey dsa;
        SECKEYDHPublicKey  dh;
        SECKEYKEAPublicKey kea;
        SECKEYFortezzaPublicKey fortezza;
        SECKEYECPublicKey  ec;
    } u;*/
    { rsa: SECKEYRSAPublicKey },
    ]);

const SECKEYPrivateKey = ctypes.StructType("SECKEYPrivateKey", [
    { arena: ctypes.voidptr_t }, // PLArenaPool*
    { keyType: ctypes.int }, // KeyType
    { pkcs11Slot: PK11SlotInfo.ptr },
    { pkcs11ID: ctypes.unsigned_long },  // CK_OBJECT_HANDLE
    { pkcs11IsTemp: ctypes.bool },
    { wincx: ctypes.voidptr_t },
    { staticflags: ctypes.uint32_t },
    ]);

const SECAlgorithmID = ctypes.StructType("SECAlgorithmID", [
    { algorithm: SECItem },
    { parameters: SECItem },
    ]);

const SECKEYEncryptedPrivateKeyInfo = ctypes.StructType("SECKEYEncryptedPrivateKeyInfo", [
    { arena: ctypes.voidptr_t }, // PLArenaPool*
    { algorithm: SECAlgorithmID },
    { encryptedData: SECItem },
    ]);

const PK11SymKey = ctypes.StructType("PK11SymKey"); // opaque for now
const SECKEYPrivateKeyInfo = ctypes.StructType("SECKEYPrivateKeyInfo");
const CERTCertificate = ctypes.StructType("CERTCertificate");

/**
 * Encode a SECItem
 */
function encodeSECItem(item) {
    var array = ctypes.cast(item.data,
                            ctypes.uint8_t.array(item.length).ptr).contents;
    return btoa(String.fromCharCode.apply(null, array))
           .replace(/\+/g, "-")
           .replace(/\//g, "_");
}

/**
 * Decode a SECItem
 */
function decodeSECItem(base64urldata) {
    let data = atob(base64urldata.replace(/-/g, "+").replace(/_/g, "/"));
    let item = new SECItem();
    let array_t = ctypes.uint8_t.array(data.length);
    item.type = SECItemType.siBuffer;
    item._buffer = array_t(data.split("").map(function(c) c.charCodeAt(0)));
    item.data = ctypes.cast(item._buffer.address(), ctypes.uint8_t.ptr);
    item.length = data.length;
    return item;
}

/**
 * Encrypt a private key with the given password
 * @param privateKey {SECKEYPrivateKey.ptr} The private key to encrypt
 * @param password {String} The password to encrypt with
 * @param [optional] nss3 {ctypes.Library} NSS library pointer
 * @param [optional] nspr4 {ctypes.Library} NSPR library pointer
 * @param [optional] slot {PK11SlotInfo.ptr} slot
 * @returns {Object} An object with .alg.id, .alg.params, and .data fields
 */
function encryptPrivateKey(privateKey, password="", nss3=null, nspr4=null, slot=null) {
    var free = {};
    try {
        // Make sure we have the libraries we need
        if (!nspr4) {
            nspr4 = ctypes.open(ctypes.libraryName("nspr4"));
            free.nspr4 = true;
        }
        if (!nss3) {
            nss3 = ctypes.open(ctypes.libraryName("nss3"));
            free.nss3 = true;
        }

        // Declare the functions used
        var PR_GetError =
            nspr4.declare("PR_GetError",
                          ABI,
                          ctypes.int32_t);
        var PK11_GetInternalSlot =
            nss3.declare("PK11_GetInternalSlot",
                         ABI,
                         PK11SlotInfo.ptr);
        var PK11_FreeSlot =
            nss3.declare("PK11_FreeSlot",
                         ABI,
                         ctypes.void_t,
                         PK11SlotInfo.ptr);
        var PK11_ExportEncryptedPrivKeyInfo =
            nss3.declare("PK11_ExportEncryptedPrivKeyInfo",
                         ABI,
                         SECKEYEncryptedPrivateKeyInfo.ptr,
                         PK11SlotInfo.ptr, // slot
                         SECOidTag, // algTag
                         SECItem.ptr, // pwItem
                         SECKEYPrivateKey.ptr, // pk
                         ctypes.int, // iteration
                         ctypes.voidptr_t); // wincx
        var SECKEY_DestroyEncryptedPrivateKeyInfo =
            nss3.declare("SECKEY_DestroyEncryptedPrivateKeyInfo",
                         ABI,
                         ctypes.void_t,
                         SECKEYEncryptedPrivateKeyInfo.ptr,
                         ctypes.bool);

        if (!slot) {
            slot = PK11_GetInternalSlot();
            if (!slot) {
                throw { rv: PR_GetError() || -1,
                        message: "Failed to get internal slot" };
            }
            free.slot = true;
        }

        password = unescape(encodeURIComponent(password)); // cast UTF8 -> bytes
        let passwordItem = new SECItem();
        passwordItem.type = SECItemType.siBuffer;
        passwordItem._buffer = ctypes.uint8_t.array(password.length)
                                    ([password.charCodeAt(i) for (i in range(password.length))]);
        passwordItem.data = ctypes.cast(passwordItem._buffer.address(),
                                        ctypes.uint8_t.ptr);
        passwordItem.length = passwordItem._buffer.length;
        var privateKeyInfo = PK11_ExportEncryptedPrivKeyInfo(slot,
                                                             SEC_OID_AES_256_CBC,
                                                             passwordItem.address(),
                                                             privateKey,
                                                             1,
                                                             null);
        if (!privateKeyInfo)
            throw { rv: PR_GetError() || -1,
                    message: "Failed to encrypt private key" };

        return {
            alg: {
                id: encodeSECItem(privateKeyInfo.contents.algorithm.algorithm),
                params: encodeSECItem(privateKeyInfo.contents.algorithm.parameters),
            },
            data: encodeSECItem(privateKeyInfo.contents.encryptedData),
        };

    } finally {
        if (privateKeyInfo && !privateKeyInfo.isNull())
            SECKEY_DestroyEncryptedPrivateKeyInfo(privateKeyInfo, true);
        if (("slot" in free) && slot)
            PK11_FreeSlot(slot);
        if (("nss3" in free) && nss3)
            nss3.close();
        if (("nspr4" in free) && nspr4)
            nspr4.close();
    }
}

/**
 * Decrypts a previously encrypted private key
 * @param publicKey {Object} Public key info; must have .alg field, and for
 *      RSA-based algorithms, have a .mod field
 * @param encryptedPrivateKey {Object} the previously encrypted private key;
 *      must have .alg.id, .alg.params, and .data fields
 * @param password {String} The password to decrypt with
 * @param [optional] nss3 {ctypes.Library} NSS library pointer
 * @param [optional] nspr4 {ctypes.Library} NSPR library pointer
 * @param [optional] slot {PK11SlotInfo.ptr} slot
 * @returns SECKEYPrivateKey.ptr
 * @note The caller must call SECKEY_DestroyPrivateKey on the return value
 */
function decryptPrivateKey(publicKey, encryptedPrivateKey,
                           password="", nss3=null, nspr4=null, slot=null) {
    var free = {};
    try {
        // Make sure we have the libraries we need
        if (!nspr4) {
            nspr4 = ctypes.open(ctypes.libraryName("nspr4"));
            free.nspr4 = true;
        }
        if (!nss3) {
            nss3 = ctypes.open(ctypes.libraryName("nss3"));
            free.nss3 = true;
        }

        // Declare the functions used
        var PR_GetError =
            nspr4.declare("PR_GetError",
                          ABI,
                          ctypes.int32_t);
        var PK11_GetInternalSlot =
            nss3.declare("PK11_GetInternalSlot",
                         ABI,
                         PK11SlotInfo.ptr);
        var PK11_FreeSlot =
            nss3.declare("PK11_FreeSlot",
                         ABI,
                         ctypes.void_t,
                         PK11SlotInfo.ptr);
        var PK11_GetKeyType =
            nss3.declare("PK11_GetKeyType",
                         ABI,
                         CK_MECHANISM_TYPE,
                         CK_MECHANISM_TYPE, // type
                         ctypes.unsigned_long); // len
        var PK11_ImportEncryptedPrivateKeyInfoAndReturnKey =
            nss3.declare("PK11_ImportEncryptedPrivateKeyInfoAndReturnKey",
                         ABI,
                         SECStatus,
                         PK11SlotInfo.ptr, // slot
                         SECKEYEncryptedPrivateKeyInfo.ptr, // epki
                         SECItem.ptr, // pwitem
                         SECItem.ptr, // nickname
                         SECItem.ptr, // publicValue
                         ctypes.bool, // isPerm
                         ctypes.bool, // isPrivate
                         ctypes.int, // type
                         ctypes.unsigned_int, // usage
                         SECKEYPrivateKey.ptr.ptr, // privk
                         ctypes.voidptr_t); // wincx

        if (!slot) {
            slot = PK11_GetInternalSlot();
            if (!slot) {
                throw { rv: PR_GetError() || -1,
                        message: "Failed to get internal slot" };
            }
            free.slot = true;
        }

        // Load the public key
        var publicValue, usage, keyType, tag;
        if (/^RS/.test(publicKey.alg)) {
            publicValue = decodeSECItem(publicKey.mod);
            usage = [CKA_SIGN, CKA_DECRYPT, CKA_SIGN_RECOVER, CKA_UNWRAP];
            keyType = PK11_GetKeyType(CKM_RSA_PKCS_KEY_PAIR_GEN, 0);
            const tags = {
                RS256: SEC_OID_PKCS1_SHA256_WITH_RSA_ENCRYPTION,
                RS384: SEC_OID_PKCS1_SHA384_WITH_RSA_ENCRYPTION,
                RS512: SEC_OID_PKCS1_SHA512_WITH_RSA_ENCRYPTION,
            }
            if (!(publicKey.alg in tags)) {
                throw { rv: -1,
                        message: "public key uses unsupported algorithm " +
                                 publicKey.alg };
            }
            tag = tags[publicKey.alg];
        } else {
            throw { rv: -1,
                    message: "public key uses unsupport algorithm family " +
                             publicKey.alg };
        }
        let usageItem = CK_ATTRIBUTE_TYPE.array(usage.length)(usage);

        password = unescape(encodeURIComponent(password)); // cast UTF8 -> bytes
        let passwordItem = new SECItem();
        passwordItem.type = SECItemType.siBuffer;
        passwordItem._buffer = ctypes.uint8_t.array(password.length)
                                    ([password.charCodeAt(i) for (i in range(password.length))]);
        passwordItem.data = ctypes.cast(passwordItem._buffer.address(),
                                        ctypes.uint8_t.ptr);
        passwordItem.length = passwordItem._buffer.length;

        let nickname = new SECItem(0, null, 0);
        var privkey = new SECKEYPrivateKey.ptr();
        let epki = new SECKEYEncryptedPrivateKeyInfo();
        epki.arena = null;
        epki.algorithm = new SECAlgorithmID();
        epki.algorithm.algorithm = decodeSECItem(encryptedPrivateKey.alg.id);
        epki.algorithm.parameters = decodeSECItem(encryptedPrivateKey.alg.params);
        epki.encryptedData = decodeSECItem(encryptedPrivateKey.data);

        var rv = PK11_ImportEncryptedPrivateKeyInfoAndReturnKey(slot,
                                                                epki.address(),
                                                                passwordItem.address(),
                                                                nickname.address(),
                                                                publicValue.address(),
                                                                false,
                                                                false,
                                                                keyType,
                                                                CKA_SIGN,
                                                                privkey.address(),
                                                                null);
        if (rv || privkey.isNull()) {
            throw { rv: PR_GetError() || -1,
                    message: "Failed to import private key" };
        }

        return privkey;

    } finally {
        if (("slot" in free) && slot)
            PK11_FreeSlot(slot);
        if (("nss3" in free) && nss3)
            nss3.close();
        if (("nspr4" in free) && nspr4)
            nspr4.close();
    }
}

/**
 * Generate a key pair
 */
function generate(params) {
    try {
        var nspr4 = ctypes.open(ctypes.libraryName("nspr4"));
        var PR_GetError =
            nspr4.declare("PR_GetError",
                          ABI,
                          ctypes.int32_t);
        var nss3 = ctypes.open(ctypes.libraryName("nss3"));
        var PK11_GetInternalSlot =
            nss3.declare("PK11_GetInternalSlot",
                         ABI,
                         PK11SlotInfo.ptr);
        var PK11_FreeSlot =
            nss3.declare("PK11_FreeSlot",
                         ABI,
                         ctypes.void_t,
                         PK11SlotInfo.ptr);
        var PK11_GenerateKeyPair =
            nss3.declare("PK11_GenerateKeyPair",
                         ABI,
                         SECKEYPrivateKey.ptr,
                         PK11SlotInfo.ptr, // slot
                         CK_MECHANISM_TYPE, // type
                         ctypes.voidptr_t, // param
                         SECKEYPublicKey.ptr.ptr, // pubk
                         ctypes.bool, // isPerm
                         ctypes.bool, // isSensitive
                         ctypes.voidptr_t); // wincx
        var SECKEY_DestroyPublicKey =
            nss3.declare("SECKEY_DestroyPublicKey",
                         ABI,
                         ctypes.void_t,
                         SECKEYPublicKey.ptr);
        var SECKEY_DestroyPrivateKey =
            nss3.declare("SECKEY_DestroyPrivateKey",
                         ABI,
                         ctypes.void_t,
                         SECKEYPrivateKey.ptr);

        var slot = PK11_GetInternalSlot();
        if (!slot) {
            throw { rv: PR_GetError() || -1,
                    message: "Failed to get PK11 internal slot" };
        }

        var genParams, mechanism;
        if (/^RS/.test(params.alg)) {
            const CKM_RSA_PKCS_KEY_PAIR_GEN = 0x00000000;
            var PK11RSAGenParams = ctypes.StructType("PK11RSAGenParams", [
                { keySizeInBits: ctypes.int },
                { pe: ctypes.unsigned_long },
            ]);
            genParams = new PK11RSAGenParams;
            genParams.keySizeInBits = parseInt(params.alg.substr(2), 10) * 8;
            genParams.pe = 0x10001; // 65537
            mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;
        }
        var publicKey = SECKEYPublicKey.ptr();
        var privateKey = PK11_GenerateKeyPair(slot,
                                              mechanism,
                                              genParams.address(),
                                              publicKey.address(),
                                              false,
                                              true,
                                              null);
        if (privateKey.isNull()) {
            throw {rv: PR_GetError() || -1,
                   message: "No private key generated"};
        }
        if (publicKey.isNull()) {
            throw {rv: -1,
                   message: "PK11_GnerateKeyPair returned private key without public key"};
        }

        // Export the private key so we can save it.
        // TODO: figure out how we can leave it on the slot and ask for it later
        var privateKeyData = encryptPrivateKey(privateKey, "", nss3, nspr4, slot);
        let pubkeyData = { alg: params.alg };
        if (/^RS/.test(params.alg)) {
            pubkeyData.algorithm = "RS";
            pubkeyData.mod = encodeSECItem(publicKey.contents.rsa.modulus);
            pubkeyData.exp = encodeSECItem(publicKey.contents.rsa.publicExponent);
        }
        return postMessage({ rv: 0,
                             pubkey: pubkeyData,
                             privateKey: privateKeyData});
    } finally {
        // clean up
        if (publicKey && !publicKey.isNull())
            SECKEY_DestroyPublicKey(publicKey);
        if (privateKey && !privateKey.isNull())
            SECKEY_DestroyPrivateKey(privateKey);
        if (slot)
            PK11_FreeSlot(slot);
        if (nss3)
            nss3.close();
        if (nspr4)
            nspr4.close();
    }
}

/**
 * Sign data
 * params are expected to be:
 * @param data {String} The data to sign
 * @param pubkey.alg {String} Algorithm to sign with
 * @param pubkey.mod {String} (RSA) base64url encoded RSA modulus
 * @param pubkey.exp {String} (RSA) base64url encoded RSA exponent
 * @param privkey.mechanism {int} Mechanism used to wrap private key
 * @param privkey.wrappingKey {String} base64url encoded symmetric key used to wrap
 * @param privkey.wrappedKey {String} base64url encoded wrapped private key
 */
function sign(params) {
    try {
        var nspr4 = ctypes.open(ctypes.libraryName("nspr4"));
        var PR_GetError =
            nspr4.declare("PR_GetError",
                          ABI,
                          ctypes.int32_t);
        var nss3 = ctypes.open(ctypes.libraryName("nss3"));
        var SECKEY_DestroyPrivateKey =
            nss3.declare("SECKEY_DestroyPrivateKey",
                         ABI,
                         ctypes.void_t,
                         SECKEYPrivateKey.ptr);
        var SEC_SignData =
            nss3.declare("SEC_SignData",
                         ABI,
                         SECStatus,
                         SECItem.ptr, // result
                         ctypes.uint8_t.ptr, // buf
                         ctypes.int, // len
                         SECKEYPrivateKey.ptr, // pk
                         SECOidTag); // tag

        var privkey = decryptPrivateKey(params.pubkey,
                                        params.privkey,
                                        "",
                                        nss3, nspr4);
        if (!privkey || privkey.isNull()) {
            throw { rv: -1,
                    message: "Failed to decrypt private key" };
        }

        var tag;
        if (/^RS/.test(params.pubkey.alg)) {
            const tags = {
                RS256: SEC_OID_PKCS1_SHA256_WITH_RSA_ENCRYPTION,
                RS384: SEC_OID_PKCS1_SHA384_WITH_RSA_ENCRYPTION,
                RS512: SEC_OID_PKCS1_SHA512_WITH_RSA_ENCRYPTION,
            }
            if (!(params.pubkey.alg in tags)) {
                throw { rv: -1,
                        message: "public key uses unsupported algorithm " +
                                 params.pubkey.alg };
            }
            tag = tags[params.pubkey.alg];
        } else {
            throw { rv: -1,
                    message: "public key uses unsupport algorithm family " +
                             params.pubkey.alg };
        }

        let signedData = new SECItem();
        signedData.type = SECItemType.siClearDataBuffer;
        signedData.length = 4096;
        signedData._buffer = ctypes.uint8_t.array(signedData.length)();
        signedData.data = ctypes.cast(signedData._buffer.address(),
                                      ctypes.uint8_t.ptr);
        let buf = ctypes.uint8_t.array(params.data.length)
                    (params.data.split("").map(function(c) c.charCodeAt(0)));
        rv = SEC_SignData(signedData.address(),
                          ctypes.cast(buf.address(), ctypes.uint8_t.ptr),
                          buf.length,
                          privkey,
                          tag);
        if (rv) {
            throw { rv: PR_GetError() || -1,
                    message: "Failed to sign data" };
        }
        postMessage({rv: 0, signature: encodeSECItem(signedData)});

    } finally {
        // clean up
        if (privkey)
            SECKEY_DestroyPrivateKey(privkey);
        if (nss3)
            nss3.close();
        if (nspr4)
            nspr4.close();
    }
}

function encrypt(params) {
    try {
        var nss3 = ctypes.open(ctypes.libraryName("nss3"));
        var SECKEY_DestroyPrivateKey =
            nss3.declare("SECKEY_DestroyPrivateKey",
                         ABI,
                         ctypes.void_t,
                         SECKEYPrivateKey.ptr);
        var privkey = decryptPrivateKey(params.publicKey, params.privateKey,
                                        params.decryptPassword);
        postMessage({ rv: 0,
                      result: encryptPrivateKey(privkey,
                                                params.encryptPassword) });
    } catch (ex) {
        postMessage({log: String(ex)});
        throw(ex);
    } finally {
        // clean up
        if (privkey)
            SECKEY_DestroyPrivateKey(privkey);
        if (nss3)
            nss3.close();
    }
}

self.onmessage = function cryptoWorker_onMessage(event) {
    let command = ("command" in event.data) ? event.data.command : String(event.data);
    try {
        switch(command) {
            case "generate":
                return generate(event.data);
            case "sign":
                return sign(event.data);
            case "encrypt":
                return encrypt(event.data);
            default:
                postMessage({rv: -1,
                             message: "Unknown command " + command});
                return null;
        }
    } catch (ex) {
        postMessage({rv: "rv" in ex ? ex.rv : -1,
                     message: String(ex.lineNumber) + " :\n" +
                              String("message" in ex ? ex.message : ex)});
        throw(ex);
    }
    return null;
};
