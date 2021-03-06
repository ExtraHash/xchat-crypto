import { KeyRingUtils } from "@extrahash/keyring";
import * as bip39 from "bip39";
import createHmac from "create-hmac";
import ed2curve from "ed2curve";
import hkdf from "futoin-hkdf";
import msgpack from "msgpack-lite";
import nacl from "tweetnacl";
import { XTypes } from "xchat-types";

/**
 * Provides an interface that can map an ed25519 keypair to its equivalent
 * X25519 keypair.
 */
export const XKeyConvert = ed2curve;

/**
 * Provides several methods that are useful in working with bytes and
 * vex messages.
 */
export class XUtils extends KeyRingUtils {
    /**
     * Checks if two buffer-like objects are equal.
     *
     * @param buf1
     * @param buf2
     *
     * @returns True if equal, else false.
     */
    public static bytesEqual(buf1: ArrayBufferLike, buf2: ArrayBufferLike) {
        if (buf1.byteLength !== buf2.byteLength) {
            return false;
        }
        const dv1 = new Int8Array(buf1);
        const dv2 = new Int8Array(buf2);
        for (let i = 0; i !== buf1.byteLength; i++) {
            if (dv1[i] !== dv2[i]) {
                return false;
            }
        }
        return true;
    }

    /**
     * Returns a six bit Uint8Array representation of an integer.
     * The integer must be positive, and it must be able to be stored
     * in six bytes.
     *
     * @param n The number to convert.
     * @returns The Uint8Array representation of n.
     */
    public static numberToUint8Arr(n: number): Uint8Array {
        let str = n.toString(16);
        while (str.length < 12) {
            str = "0" + str;
        }
        return XUtils.decodeHex(str);
    }

    /**
     * Converts a Uint8Array representation of an integer back into a number.
     *
     * @param arr The array to convert.
     * @returns the number representation of arr.
     */
    public static uint8ArrToNumber(arr: Uint8Array) {
        return Buffer.from(arr).readUIntBE(0, arr.length);
    }

    /**
     * Takes a vex message and unpacks it into its header and a javascript object
     * respresentation of its body.
     *
     * @param arr The array to convert.
     * @returns [32 byte header, message body]
     */
    public static unpackMessage(msg: Buffer): [Uint8Array, XTypes.WS.IBaseMsg] {
        const msgp = Uint8Array.from(msg);
        const msgh = msgp.slice(0, xConstants.HEADER_SIZE);
        const msgb = msgpack.decode(msgp.slice(xConstants.HEADER_SIZE));

        return [msgh, msgb];
    }

    /**
     * Packs a javascript object and a 32 byte header into a vex message.
     *
     * @param arr The array to convert.
     * @returns the packed message.
     */
    public static packMessage(msg: any, header?: Uint8Array): Uint8Array {
        const msgb = Uint8Array.from(msgpack.encode(msg));
        const msgh = header || XUtils.emptyHeader();
        return xConcat(msgh, msgb);
    }

    /**
     * Returns the empty header (32 0's)
     *
     * @returns The empty header.
     */
    public static emptyHeader(): Uint8Array {
        return new Uint8Array(xConstants.HEADER_SIZE);
    }

    /**
     * Decodes a hex string into a Uint8Array.
     *
     * @returns The Uint8Array.
     */
    public static decodeHex(hexString: string, length?: number): Uint8Array {
        if (hexString.length === 0) {
            return new Uint8Array();
        }

        return new Uint8Array(
            hexString.match(/.{1,2}/g)!.map((byte) => parseInt(byte, 16))
        );
    }

    /**
     * Encodes a Uint8Array to a hex string.
     *
     * @returns The hex string.
     */
    public static encodeHex(bytes: Uint8Array): string {
        return bytes.reduce(
            (str, byte) => str + byte.toString(16).padStart(2, "0"),
            ""
        );
    }
}

/**
 * Gets a word list representation of a byte sequence.
 *
 * @param entropy The bytes to derive the wordlist from.
 * @param wordList Optional, override the wordlist. See bip39 docs for details.
 */
export function xMnemonic(
    entropy: Uint8Array,
    wordList?: string[] | undefined
) {
    return bip39.entropyToMnemonic(Buffer.from(entropy), wordList);
}

/**
 * Returns a 32 byte HMAC of a javscript object.
 *
 * @param msg the message to create the HMAC of
 * @param SK the secret key to create the HMAC with
 */
export function xHMAC(msg: any, SK: Uint8Array) {
    const packedMsg = Uint8Array.from(msgpack.encode(msg));
    const hmacGen = createHmac("sha256", Buffer.from(SK));
    hmacGen.update(packedMsg);
    const hmac = Uint8Array.from(hmacGen.digest());
    return hmac;
}

/**
 * Constants for vex.
 */
export const xConstants: XConstants = {
    CURVE: "X25519",
    HASH: "SHA-512",
    KEY_LENGTH: 32,
    INFO: "xchat",
    MIN_OTK_SUPPLY: 100,
    HEADER_SIZE: 32,
};

/**
 * Returns a 24 byte random nonce of cryptographic quality.
 */
export function xMakeNonce(): Uint8Array {
    return nacl.randomBytes(24);
}

/**
 * Derives a 32 byte secret key from some initial key material.
 *
 * @param IKM the initial key material.
 * @returns The generated key.
 */
export function xKDF(IKM: Uint8Array): Uint8Array {
    return Uint8Array.from(
        hkdf(Buffer.from(IKM), xConstants.KEY_LENGTH, {
            salt: Buffer.from(xMakeSalt(xConstants.CURVE)),
            info: xConstants.INFO,
            hash: xConstants.HASH,
        })
    );
}

/**
 * Derives a shared Secret Key from a known private key and
 * a peer's known public key.
 *
 * @param myPrivateKey Your own private key
 * @param theirPublicKey Their public key
 * @returns The derived shared secret, SK.
 */
export function xDH(
    myPrivateKey: Uint8Array,
    theirPublicKey: Uint8Array
): Uint8Array {
    return nacl.box.before(theirPublicKey, myPrivateKey);
}

/**
 * Concatanates multiple Uint8Arrays.
 *
 * @param arrays As many Uint8Arrays as you would like to concatanate.
 */
export function xConcat(...arrays: Uint8Array[]): Uint8Array {
    // sum of individual array lengths
    const totalLength = arrays.reduce((acc, value) => acc + value.length, 0);

    if (!arrays.length) {
        return new Uint8Array();
    }

    const result = new Uint8Array(totalLength);

    // for each array - copy it over result
    // next array is copied right after the previous one
    let length = 0;
    for (const array of arrays) {
        result.set(array, length);
        length += array.length;
    }

    return result;
}

/**
 * Encode an X25519 or X448 public key PK into a byte sequence.
 * The encoding consists of 0 or 1 to represent the type of curve, followed by l
 * ittle-endian encoding of the u-coordinate. See [rfc 7748](https://www.ietf.org/rfc/rfc7748.txt) for more
 * details.
 */
export function xEncode(
    curveType: "X25519" | "X448",
    publicKey: Uint8Array
): Uint8Array {
    if (publicKey.length !== 32) {
        throw new Error(
            "Invalid key length, received key of length " +
                publicKey.length +
                " and expected length 32."
        );
    }

    const bytes: number[] = [];

    switch (curveType) {
        case "X25519":
            bytes.push(0);
            break;
        case "X448":
            bytes.push(1);
            break;
    }

    const key = BigInt("0x" + XUtils.encodeHex(publicKey));

    if (isEven(key)) {
        bytes.push(0);
    } else {
        bytes.push(1);
    }

    for (const byte of publicKey) {
        bytes.push(byte);
    }

    return Uint8Array.from(bytes);
}

/**
 * @ignore
 */
function keyLength(curve: "X25519" | "X448"): number {
    return curve === "X25519" ? 32 : 57;
}

/**
 * @ignore
 */
function xMakeSalt(curve: "X25519" | "X448"): Uint8Array {
    const saltLength = keyLength(curve);

    const salt = new Uint8Array(saltLength);
    for (let i = 0; i < saltLength; i++) {
        salt.set([0xff]);
    }

    return salt;
}

/**
 * @ignore
 */
function isEven(value: bigint) {
    if (value % BigInt(2) === BigInt(0)) {
        return true;
    } else {
        return false;
    }
}

/**
 * @ignore
 */
// tslint:disable-next-line: interface-name
interface XConstants {
    CURVE: "X25519";
    HASH: "SHA-512";
    INFO: string;
    KEY_LENGTH: 32 | 57;
    MIN_OTK_SUPPLY: number;
    HEADER_SIZE: 32;
}
