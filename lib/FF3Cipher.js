/*
 * Format-Preserving Encryption for FF3
 *
 * Copyright (c) 2021 Schoening Consulting LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and limitations under the License.
 */

const crypto = require('crypto')

const DOMAIN_MIN =  1000000;  // 1M is currently recommended in FF3-1
const NUM_ROUNDS =   8;
const BLOCK_SIZE =   16;      // AES BlockSize
const TWEAK_LEN =    8;       // Original FF3 64-bit tweak length
const TWEAK_LEN_NEW =7;       // FF3-1 56-bit tweak length
const HALF_TWEAK_LEN = TWEAK_LEN/2;
const MAX_RADIX =    36;      // BigInt supports radix 2..36

function reverseString(s) {
    return s.split('').reverse().join('');
}

// We use Number.parseInt unless length of A or B is gt 9

function convertToBigInt(value, radix) { // value: string
    let size = 10
    let factor = BigInt(radix) ** BigInt(size)
    let i = value.length % size || size
    let parts = [value.slice(0, i)];

    while (i < value.length) parts.push(value.slice(i, i += size));

    return parts.reduce((r, v) => r * factor + BigInt(parseInt(v, radix)), 0n);
}

function bigToUint8Array(big) {
    if (big < 0n) {
        const bits = (BigInt(big.toString(2).length) / 8n + 1n) * 8n
        const prefix = 1n << bits
        big += prefix
    }
    let hex = big.toString(16)
    if (hex.length % 2) {
        hex = '0' + hex
    }
    const len = hex.length / 2
    const u8 = new Uint8Array(len)
    let i = 0
    let j = 0
    while (i < len) {
        u8[i] = parseInt(hex.slice(j, j + 2), 16)
        i += 1
        j += 2
    }
    return u8;
}

class FF3Cipher {

    constructor( key, tweak, radix=10) {
        // Class FF3Cipher implements the FF3 format-preserving encryption algorithm
        this.radix = radix;
        let keyBytes = Buffer.from(key, 'hex').reverse();

        // Calculate range of supported message lengths [minLen..maxLen]
        // radix 10: 6 ... 56, 26: 5 ... 40, 36: 4 .. 36

        // Per revised spec, radix^minLength >= 1,000,000
        this.minLen = Math.ceil(Math.log(DOMAIN_MIN) / Math.log(radix));

        // We simplify the specs log[radix](2^96) to 96/log2(radix) using the log base change rule
        this.maxLen = (2 * Math.floor(Math.log(2**96)/Math.log(radix)));

        const keyLen = keyBytes.length;

        // Check if the key is 128, 192, or 256 bits = 16, 24, or 32 bytes
        let algo = 'unknown'
        switch (keyBytes.length) {
            case 16:
                algo = "aes-128-ecb";
                break;
            case 24:
                algo = "aes-192-ecb";
                break;
            case 32:
                algo = "aes-256-ecb";
                break;
            default:
                throw("key length " + keyLen + " but must be 128, 192, or 256 bits");
        }

        // While FF3 allows radices in [2, 2^16], there is a practical limit to 36 (alphanumeric)
        // because Java BigInt only supports up to base 36.
        if ((radix < 2) || (radix > MAX_RADIX)) {
            throw ("radix must be between 2 and 36, inclusive");
        }

        // Make sure 2 <= minLength <= maxLength < 2*floor(log base radix of 2^96) is satisfied
        if ((this.minLen < 2) || (this.maxLen < this.minLen)) {
            // ||((float) this.maxLen > (192 / Math.log2((float)(radix))))){
            throw ("minLen or maxLen invalid, adjust your radix");
        }

        this.tweakBytes = Buffer.from(tweak, 'hex');
		if (this.tweakBytes.length == TWEAK_LEN_NEW) {
			this.tweakBytes = FF3Cipher.calculateTweak64_FF3_1(this.tweakBytes);
		}

        // AES block cipher in ECB mode with the block size derived based on the length of the key
        // Always use the reversed key since Encrypt and Decrypt call cipher expecting that
        // Feistel ciphers use the same func for encrypt/decrypt, so mode is always ENCRYPT_MODE

        this.aesCipher = crypto.createCipheriv(algo, keyBytes, '')
        this.aesCipher.setAutoPadding(false)
    }

    // Javascript % is remainder

    static mod(n, m) { return ((n % m) + m) % m; }

    static calculateP(i, radix, W, B) {

        let P = new Uint8Array(BLOCK_SIZE);     // P is always 16 bytes, zero initialized

        // Calculate P by XORing W, i into the first 4 bytes of P
        // i only requires 1 byte, rest are 0 padding bytes
        // Anything XOR 0 is itself, so only need to XOR the last byte

        P[0] = W[0];
        P[1] = W[1];
        P[2] = W[2];
        P[3] = (W[3] ^ i);

        // The remaining 12 bytes of P are copied from reverse(B) with padding

        B = reverseString(B);
        let big = convertToBigInt(B, radix);
        let bBytes = bigToUint8Array(big);
        P.set(bBytes, BLOCK_SIZE-bBytes.length);
        // console.log("round: %d W: %s P: %s", i, W.toString('hex'), P.toString());
        return P;
    }

    static calculateTweak64_FF3_1(tweak56) {
        let tweak64 = Buffer.alloc(8);
        tweak64[0] = tweak56[0];
        tweak64[1] = tweak56[1];
        tweak64[2] = tweak56[2];
        tweak64[3] = (tweak56[3] & 0xF0);
        tweak64[4] = tweak56[4];
        tweak64[5] = tweak56[5];
        tweak64[6] = tweak56[6];
        tweak64[7] = ((tweak56[3] & 0x0F) << 4);

        //console.log("orig tweak: %s new tweak: %s %s", tweak56.toString('hex'), tweak64.slice(0,4).toString('hex'), 
        //    tweak64.slice(4,8).toString('hex'));
        return tweak64;
    }


    /* convenience method to override tweak */
    ///encrypt(plaintext, tweak) {
    //    this.tweakBytes = HexStringToByteArray(tweak);
    //    return encrypt(plaintext);
    //}

    encrypt(plaintext) {
        const n = plaintext.length;

        // Check if message length is within minLength and maxLength bounds
        if ((n < this.minLen) || (n > this.maxLen)) {
            throw `message length ${n} is not within min ${this.minLen} and max ${this.maxLen} bounds`;
        }

        // Make sure the given the length of tweak in bits is 56 or 64
        if ((this.tweakBytes.length !== TWEAK_LEN) && (this.tweakBytes.length !== TWEAK_LEN_NEW)) {
            throw `tweak length ${this.tweakBytes.length} is invalid: tweak must be 56 or 64 bits`
        }

        // Check if the plaintext message is formatted in the current radix
        // ToDo: replace this as its too expensive to check every time
        try {
            // convertToBigInt(plaintext, this.radix)
        } catch (ex) {
            throw `Plaintext ${plaintext} is not supported in the current radix ${this.radix} ${ex}`;
        }

        // Calculate split point
        const u = Math.ceil(n / 2.0);
        const v = n - u;

        // Split the message
        let A = plaintext.substring(0,u);
        let B = plaintext.substring(u);
        // console.log("r %d A %s B %s", this.radix, A, B);

        // Split the tweak
        const Tl = this.tweakBytes.slice(0,HALF_TWEAK_LEN);
        const Tr = this.tweakBytes.slice(HALF_TWEAK_LEN, TWEAK_LEN);

        // P is always 16 bytes
        let P;

        // Pre-calculate the modulus since it's only one of 2 values,
        // depending on whether i is even or odd

        const modU = BigInt(this.radix)**BigInt(u);
        const modV = BigInt(this.radix)**BigInt(v);

        // Note: Use BigInt with the ** instead of Math.pow(10,20) which returns a float may incorrectly round result 
        // greater than Number.MAX_SAFE_INTEGER.

        // console.log("u %d v %d modU: %d modV: %d", u, v, modU, modV);
        // console.log("tL: %s tR: %s", Tl.toString('hex'), Tr.toString('hex'));

        for (let i = 0; i < NUM_ROUNDS; ++ i) {
            let m;
            let c;
            let W;

            // Determine alternating Feistel round side, right or left
            if (i % 2 === 0) {
                m = u;
                W = Tr;
            } else {
                m = v;
                W = Tl;
            }

            // P is fixed-length 16 bytes
            P = FF3Cipher.calculateP( i, this.radix, W, B);
            P.reverse();

            // Calculate S by operating on P in place
            let S = this.aesCipher.update(P);

            S.reverse();
            // console.log("\tS: %s", S.toString('hex'));

            let y = BigInt('0x' + S.toString('hex'));

            // Calculate c
            try {
                //c = BigInt(reverseString(A), this.radix);
                c = convertToBigInt(reverseString(A), this.radix);
            } catch (ex) {
                throw("string A is not within base/radix " + this.radix);
            }

            c = c + y;

            if (i % 2 === 0) {
                c = FF3Cipher.mod(c, modU);
            } else {
                c = FF3Cipher.mod(c, modV);
            }

            // console.log("\tm: %d A: %s c: %d y: %d", m, A, c, y);

            // Convert c to sting using radix and length m
            let C = c.toString(this.radix);
            C = reverseString(C);
            C = C + "00000000".substring(0,m-C.length);

            // Final steps
            A = B;
            B = C;
            // console.log("A: %s B: %s", A, B);
        }
        return A+B;
    }

    /* convenience method to override tweak */
/*
    decrypt(ciphertext, tweak) throws BadPaddingException, IllegalBlockSizeException {
        this.tweakBytes = HexStringToByteArray(tweak);
        return decrypt(ciphertext);
    }
*/

    decrypt(ciphertext) {
        let n = ciphertext.length;

        // Check if message length is within minLength and maxLength bounds
        if ((n < this.minLen) || (n > this.maxLen)) {
            throw `message length ${n} is not within min ${this.minLen} and max ${this.maxLen} bounds`;
        }

        // Make sure the given the length of tweak in bits is 56 or 64
        if ((this.tweakBytes.length !== TWEAK_LEN) && (this.tweakBytes.length !== TWEAK_LEN_NEW)) {
            throw `tweak length ${this.tweakBytes.length} is invalid: tweak must be 56 or 64 bits`
        }

        // Check if the ciphertext message is formatted in the current radix
        // ToDo: replace this as its too expensive to check every time
        try {
            //BigInt(ciphertext, this.radix);
            //convertToBigInt(ciphertext, this.radix);
        } catch (ex) {
            throw ex;
            //throw "The ciphertext is not supported in the current radix %d", this.radix
        }

        // Calculate split point
        const u = Math.ceil(n / 2.0);
        const v = n - u;

        // Split the message
        let A = ciphertext.substring(0,u);
        let B = ciphertext.substring(u);

        // Split the tweak
        const Tl = this.tweakBytes.slice(0,HALF_TWEAK_LEN);
        const Tr = this.tweakBytes.slice(HALF_TWEAK_LEN, TWEAK_LEN);

        // P is always 16 bytes
        let P;

        // Pre-calculate the modulus since it's only one of 2 values,
        // depending on whether i is even or odd

        const modU = BigInt(this.radix)**BigInt(u);
        const modV = BigInt(this.radix)**BigInt(v);
        // console.log("u %d v %d modU: %d modV: %d", u, v, modU, modV);
        // console.log("tL: %s tR: %s", Tl.toString('hex'), Tr.toString('hex'));

        for (let i = (NUM_ROUNDS-1); i >= 0; --i) {
            let m;
            let c;
            let W;

            // Determine alternating Feistel round side, right or left
            if (i % 2 === 0) {
                m = u;
                W = Tr;
            } else {
                m = v;
                W = Tl;
            }

            // P is fixed-length 16 bytes
            P = FF3Cipher.calculateP( i, this.radix, W, A);
            P.reverse();

            // Calculate S by operating on P in place
            let S = this.aesCipher.update(P);
            S.reverse();
            // console.log("\tS: %s", S.toString('hex'));

            let y = BigInt('0x' + S.toString('hex'));

            // Calculate c
            try {
                c = convertToBigInt(reverseString(B), this.radix);
                // console.log("\tin: %s out: %d", reverseString(B).toString('hex'), c);
            } catch (ex) {
                throw("string B is not within base/radix " + this.radix);
            }

            c = c - y;

            if (i % 2 === 0) {
                c = FF3Cipher.mod(c, modU); //c % modU;
            } else {
                c = FF3Cipher.mod(c, modV); //c % modV;
            }

            // console.log("\tm: %d B: %s c: %d y: %d", m, B, c, y);

            // Convert c to sting using radix and length m
            let C = c.toString(this.radix);
            C = reverseString(C);
            C = C + "00000000".substring(0,m-C.length);

            // Final steps
            B = A;
            A = C;
            // console.log("A: %s B: %s", A, B);
        }
        return A+B;
    }


}

module.exports = FF3Cipher;

