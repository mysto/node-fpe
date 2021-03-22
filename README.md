[![Build Status](https://travis-ci.com/mysto/node-fpe.svg?branch=main)](https://travis-ci.com/mysto/node-fpe)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

# ff3 - Format Preserving Encryption in Node.js

An implementation of the NIST approved Format Preserving Encryption (FPE) FF3 algorithm in Node.js.

* [NIST Recommendation SP 800-38G](http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38G.pdf)

This package follows the FF3 algorithum for Format Preserving Encryption as described in the March 2016 NIST publication _Methods for Format-Preserving Encryption_, and revised on Feburary 28th, 2020 with a draft update for FF3-1.

Changes to minimum domain size and revised tweak length have been partially implemented in this package with updates to domain size. It is expected that the final standard will provide new test vectors necessary to change the tweak lengths to 56 bits.  Currently, tweaks remain set to 64 bits.

## Requires

This project was built and tested with Node.js 12 and later versions.  It requires the crypto library:

## Installation

tbd w/npm install

## Usage

FF3 is a Feistel ciphers, and Feistel ciphers are initialized with a radix representing an alphabet.  
Practial radix limits of 36 in python means the following radix values are typical:
* radix 10: digits 0..9
* radix 26: alphabetic a-z
* radix 36: alphanumeric 0..9, a-z

Special characters and international character sets, such as those found in UTF-8, would require a larger radix, and are not supported. 
Also, all elements in a plaintext string share the same radix. Thus, an identification number that consists of a letter followed 
by 6 digits (e.g. A123456) cannot be correctly encrypted by FPE while preserving this convention.

Input plaintext has maximum length restrictions based upon the chosen radix (2 * floor(96/log2(radix))):
* radix 10: 56 
* radix 26: 40
* radix 36: 36

To work around string length, its possible to encode longer text in chunks.

As with any cryptographic package, managing and protecting the key(s) is crucial. The tweak is generally not kept secret.
This package does not protect the key in memory.

## Code Example

The example code below can help you get started.

Using default domain [0-9]

```js

const key = "EF4359D8D580AA4F7F036D6F04FC6A94"
const tweak = "D8E7920AFA330A73"
const c = new FF3Cipher(key, tweak)

const plaintext = "4000001234567899"
let ciphertext = c.encrypt(plaintext)
let decrypted = c.decrypt(ciphertext)

console.log("Original: " + plaintext)
console.log("Ciphertext: " + ciphertext)
console.log("Decrypted: " + decrypted)

```
## Testing

There are official [test vectors](https://csrc.nist.gov/csrc/media/projects/cryptographic-standards-and-guidelines/documents/examples/ff3samples.pdf) for FF3 provided by NIST, which are used for testing in this package.

To run unit tests on this implementation, including all test vectors from the NIST specification, run the command:

  1. node test/FF3CipherTest.js

## FF3 Algorithum

The FF3 algorithum is a tweakable block cipher based on an eight round Feistel cipher. A block cipher operates on fixed-length groups of bits, called blocks. A Feistel Cipher is not a specific cipher,
but a design model.  The encryption process consisting of eight rounds of 
processing of the plaintext, each round applies an internal round function followed by transformation steps.

The FF3 round function uses AES encryption in ECB mode, which is performed each iteration 
on alternating halves of the text being encrypted. The *key* value in FF3 is used only to initialize the AES cipher. Thereafter
the *tweak* is used together with the intermediate encrypted text as input to the round function.

## Implementation Notes

This implementation follows the algorithm as outlined in the NIST specification as closely as possible, including naming.

FPE can be used for sensitive data tokenization, especially with PCI and cryptographically reversible tokens. This implementation does not provide any guarantees regarding PCI DSS or other validation.

While all test vectors pass, this package has not otherwise been extensively tested.

The standard built-in [BigInt](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/BigInt) package supports radices/bases up to 36. Therefore, this release supports a max base of 36, which can contain numeric digits 0-9 and lowercase alphabetic characters a-z.

The cryptographic library used is [crypto](https://nodejs.org/api/crypto.html) for AES encryption. FF3 uses a single-block with an IV of 0, which is effectively ECB mode. AES ECB is the only block cipher function which matches the requirement of the FF3 spec.

The domain size was revised in FF3-1 to radix<sup>minLen</sup> >= 1,000,000 and is represented by the constant `DOMAIN_MIN` in `ff3.py`. FF3-1 is in draft status and updated 56-bit test vectors are not yet available.

The tweak is required in the initial `FF3Cipher` constructor, but can optionally be overriden in each `encrypt` and `decrypt` call. This is similar to passing an IV or nonce when creating an encryptor object.

## Author

Brad Schoening

## License

This project is licensed under the terms of the [Apache 2.0 license](https://www.apache.org/licenses/LICENSE-2.0).
