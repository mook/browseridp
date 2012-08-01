/**
 * This is a ChromeWorker script for crypto operations;
 * it's done on a worker so it won't block the main thread.
 */

/**
 * utility functions
 */
function range(max) { for (let i = 0; i < max; i++) yield i; }

/**
 * ctypes declarations
 */

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

const PK11SlotInfo = ctypes.StructType("PK11SlotInfo");

const SECItem = ctypes.StructType("SECItem", [
    { typeof: ctypes.int /* SECItemType */ },
    { data: ctypes.uint8_t.ptr },
    { length: ctypes.unsigned_int },
    ]);
const SECKEYRSAPublicKey = ctypes.StructType("SECKEYRSAPublicKey", [
    { arena: ctypes.voidptr_t /* PLArenaPool * */},
    { modulus: SECItem },
    { publicExponent: SECItem },
    ]);
const SECKEYPublicKey = ctypes.StructType("SECKEYPublicKeyStr", [
    { arena: ctypes.voidptr_t /* PLArenaPool * */},
    { keyType: ctypes.int /* KeyType */ },
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
    { arena: ctypes.voidptr_t /* PLArenaPool * */},
    { keyType: ctypes.int /* KeyType */ },
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
    { arena: ctypes.voidptr_t /* PLArenaPool * */},
    { algorithm: SECAlgorithmID },
    { encryptedData: SECItem },
    ]);

/**
 * Encode a SECItem
 */
function encodeSECItem(item) {
    var s = "";
    var array = ctypes.cast(item.data,
                            ctypes.uint8_t.array(item.length).ptr).contents;
    return btoa(String.fromCharCode.apply(null, array))
           .replace(/\+/g, "-")
           .replace(/\//g, "_");
}

/**
 * Generate a key pair
 */
function generate(params) {
    try {
        var nspr4 = ctypes.open("nspr4");
        var PR_GetError = nspr4.declare("PR_GetError",
                                        ctypes.winapi_abi,
                                        ctypes.int32_t);
        var PR_GetErrorTextLength = nspr4.declare("PR_GetErrorTextLength",
                                                  ctypes.winapi_abi,
                                                  ctypes.int32_t);
        var PR_GetErrorText = nspr4.declare("PR_GetErrorText",
                                            ctypes.winapi_abi,
                                            ctypes.int32_t,
                                            ctypes.char.ptr);
        var nss3 = ctypes.open("nss3");
        var PK11_GetInternalSlot = nss3.declare("PK11_GetInternalSlot",
                                                ctypes.winapi_abi,
                                                PK11SlotInfo.ptr);
        var PK11_FreeSlot = nss3.declare("PK11_FreeSlot",
                                         ctypes.winapi_abi,
                                         ctypes.void_t,
                                         PK11SlotInfo.ptr);
        var PK11_GenerateKeyPair = nss3.declare("PK11_GenerateKeyPair",
                                                ctypes.winapi_abi,
                                                SECKEYPrivateKey.ptr, // SECKEYPrivateKey *
                                                PK11SlotInfo.ptr, // PK11SlotInfo *slot
                                                ctypes.unsigned_long, // CK_MECHANISM_TYPE type
                                                ctypes.voidptr_t, // void *param
                                                SECKEYPublicKey.ptr.ptr, // SECKEYPublicKey **pubk
                                                ctypes.bool, // PRBool isPerm
                                                ctypes.bool, // PRBool isSensitive
                                                ctypes.voidptr_t); // void *wincx
        var SECKEY_DestroyPublicKey = nss3.declare("SECKEY_DestroyPublicKey",
                                                   ctypes.winapi_abi,
                                                   ctypes.void_t,
                                                   SECKEYPublicKey.ptr);
        var SECKEY_DestroyPrivateKey = nss3.declare("SECKEY_DestroyPrivateKey",
                                                    ctypes.winapi_abi,
                                                    ctypes.void_t,
                                                    SECKEYPrivateKey.ptr);
        var PK11_ExportEncryptedPrivKeyInfo = nss3.declare("PK11_ExportEncryptedPrivKeyInfo",
                                                           ctypes.winapi_abi,
                                                           SECKEYEncryptedPrivateKeyInfo.ptr,
                                                           PK11SlotInfo.ptr,
                                                           ctypes.int, /* SECOidTag */
                                                           SECItem.ptr,
                                                           SECKEYPrivateKey.ptr,
                                                           ctypes.int,
                                                           ctypes.voidptr_t);
        var SECKEY_DestroyEncryptedPrivateKeyInfo = nss3.declare("SECKEY_DestroyEncryptedPrivateKeyInfo",
                                                                 ctypes.winapi_abi,
                                                                 ctypes.void_t,
                                                                 SECKEYEncryptedPrivateKeyInfo.ptr,
                                                                 ctypes.bool);

        var slot = PK11_GetInternalSlot();
        if (!slot) {
            throw "Failed to get PK11 internal slot";
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
            let rv = PR_GetError();
            let buffer = ctypes.char.array(PR_GetErrorTextLength() + 1)();
            PR_GetErrorText(buffer);
            throw {rv: rv,
                   message: "No private key generated"};
        }
        if (publicKey.isNull()) {
            SECKEY_DestroyPrivateKey(privateKey);
            privateKey = null;
            throw {rv: -1,
                   message: "PK11_GnerateKeyPair returned private key without public key"};
        }

        var password = new SECItem(0, null, 0);
        var privateKeyInfo = PK11_ExportEncryptedPrivKeyInfo(slot,
                                                             /* SEC_OID_AES_256_CBC */ 188,
                                                             password.address(),
                                                             privateKey,
                                                             1,
                                                             null);
        if (privateKeyInfo.isNull()) {
            throw { rv: PR_GetError() || -1,
                    message: "Failed to export private key" };
        }

        let pubkeyData = { alg: params.alg };
        if (/^RS/.test(params.alg)) {
            pubkeyData.algorithm = "RS";
            pubkeyData.mod = encodeSECItem(publicKey.contents.rsa.modulus);
            pubkeyData.exp = encodeSECItem(publicKey.contents.rsa.publicExponent);
        }
        return postMessage({ rv: 0,
                             pubkey: pubkeyData,
                             privateKey: encodeSECItem(privateKeyInfo.contents.encryptedData) });
    } finally {
        // clean up
        if (privateKeyInfo && !privateKeyInfo.isNull()) SECKEY_DestroyEncryptedPrivateKeyInfo(privateKeyInfo, true);
        if (publicKey && !publicKey.isNull()) SECKEY_DestroyPublicKey(publicKey);
        if (privateKey && !privateKey.isNull()) SECKEY_DestroyPrivateKey(privateKey);
        if (slot) PK11_FreeSlot(slot);
        if (nss3) nss3.close();
        if (nspr4) nspr4.close();
    }
}

self.onmessage = function cryptoWorker_onMessage(event) {
    let command = ("command" in event.data) ? event.data.command : String(event.data);
    try {
        switch(command) {
            case "generate":
                return generate(event.data);
            default:
                postMessage({rv: -1,
                             message: "Unknown command " + command});
                return null;
        }
    } catch (ex) {
        postMessage({rv: "rv" in ex ? ex.rv : -1 ,
                     message: String("message" in ex ? ex.message : ex)});
        throw(ex);
    }
    return null;
};
