import { KeyRingUtils } from "@extrahash/keyring";
const { encodeHex } = KeyRingUtils;

export function xEncode(
    curveType: "X25519" | "X448",
    publicKey: Uint8Array
): Uint8Array {
    console.log(publicKey.length);

    const bytes: number[] = [];

    switch (curveType) {
        case "X25519":
            bytes.push(0);
            break;
        case "X448":
            bytes.push(1);
            break;
    }

    const key = BigInt("0x" + encodeHex(publicKey));

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

function isEven(value: bigint) {
    if (value % BigInt(2) === BigInt(0)) {
        return true;
    } else {
        return false;
    }
}
