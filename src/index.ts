import { KeyRingUtils } from "@extrahash/keyring";
import ed2curve from "ed2curve";
import hkdf from "futoin-hkdf";
import nacl from "tweetnacl";

export const XKeyConvert = ed2curve;

export class XUtils extends KeyRingUtils {
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
     * Decodes a hex string into a Uint8Array.
     *
     * @returns The Uint8Array.
     */
    public static decodeHex(hexString: string): Uint8Array {
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

export const xConstants: XConstants = {
    CURVE: "X25519",
    HASH: "SHA-512",
    KEY_LENGTH: 32,
    INFO: "xchat",
    MIN_OTK_SUPPLY: 100,
};

export function xMakeNonce(): Uint8Array {
    return nacl.randomBytes(24);
}

export function xKDF(IKM: Uint8Array): Uint8Array {
    return Uint8Array.from(
        hkdf(Buffer.from(IKM), xConstants.KEY_LENGTH, {
            salt: Buffer.from(xMakeSalt(xConstants.CURVE)),
            info: xConstants.INFO,
            hash: xConstants.HASH,
        })
    );
}

export function xDH(
    myPrivateKey: Uint8Array,
    theirPublicKey: Uint8Array
): Uint8Array {
    return nacl.box.before(theirPublicKey, myPrivateKey);
}

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

function keyLength(curve: "X25519" | "X448"): number {
    return curve === "X25519" ? 32 : 57;
}

function xMakeSalt(curve: "X25519" | "X448"): Uint8Array {
    const saltLength = keyLength(curve);

    const salt = new Uint8Array(saltLength);
    for (let i = 0; i < saltLength; i++) {
        salt.set([0xff]);
    }

    return salt;
}

function isEven(value: bigint) {
    if (value % BigInt(2) === BigInt(0)) {
        return true;
    } else {
        return false;
    }
}

// tslint:disable-next-line: interface-name
interface XConstants {
    CURVE: "X25519" | "X448";
    HASH: "SHA-256" | "SHA-512";
    INFO: string;
    KEY_LENGTH: 32 | 57;
    MIN_OTK_SUPPLY: number;
}
