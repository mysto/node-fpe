const test = require('tape');
const FF3Cipher = require('../lib/FF3Cipher');
const crypto = require('crypto')

test('AES ECB encryption', (t) => {
  // NIST test vector for ECB-AES128
  t.plan(1);
  const key = Buffer.from('2b7e151628aed2a6abf7158809cf4f3c','hex');
  const pt = Buffer.from("6bc1bee22e409f96e93d7e117393172a", 'hex');
  const c = crypto.createCipheriv("aes-128-ecb", key, '')
  c.setAutoPadding(false)
  let ct = c.update(pt).toString('hex');
  t.equal(ct, "3ad77bb40d7a3660a89ecaf32466ef97");
});

test('radix', (t) => {
  t.plan(6);
  // BigInt string conversions with radix 10, 26 and 36
  t.equal((5n).toString(10),'5')
  t.equal((26n).toString(26),'10')
  t.equal((35n).toString(36),'z')
  // BigInt hex constructor
  t.equal(BigInt("0xFF"),255n)
  t.equal(Number.parseInt("z",36),35)
  t.equal(FF3Cipher.mod((706456850n - 316291629567414359958402343312719325709n ),1000000000n),987131141n)
  // Buffer.from([ 8, 6, 7, 5, 3, 0, 9]);
})

test('calculateP', (t) => {
  t.plan(1);
  // NIST Sample #1, round 0
  let i=0, radix=10;
  const B = "567890000";
  const Z = new Uint8Array([250, 51, 10, 115, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 129, 205])
  let W = Buffer.from("FA330A73",'hex');
  let P = FF3Cipher.calculateP(i, radix, W, B);
  t.deepEqual(P, Z);
});

test('encrypt-decrypt', (t) => {
  t.plan(2);

  const c = new FF3Cipher("EF4359D8D580AA4F7F036D6F04FC6A94", "D8E7920AFA330A73");
  console.log('created cipher')
  console.log(c)
  const pt = "890121234567890000";
  const ct = "750918814058654607";
  let ciphertext = c.encrypt(pt);
  let plaintext = c.decrypt(ct);
  t.equal(ct, ciphertext);
  t.equal(pt, plaintext);
});

/*
 * NIST Test Vectors for 128, 198, and 256 bit modes
 * https://csrc.nist.gov/csrc/media/projects/cryptographic-standards-and-guidelines/documents/examples/ff3samples.pdf
 */

// AES-128

test('128dot1', (t) => {
  t.plan(2);
  // Sample #1 from NIST FF3-AES128
  const c = new FF3Cipher("EF4359D8D580AA4F7F036D6F04FC6A94", "D8E7920AFA330A73", 10);
  const pt = "890121234567890000", ct = "750918814058654607";
  let ciphertext = c.encrypt(pt);
  let plaintext = c.decrypt(ciphertext);
  t.equal(ct, ciphertext);
  t.equal(pt, plaintext);
});

test('test128dot2()', (t) => {
  t.plan(2);
  // NIST FF3-AES128
  const c = new FF3Cipher("EF4359D8D580AA4F7F036D6F04FC6A94", "9A768A92F60E12D8", 10);
  const pt = "890121234567890000", ct = "018989839189395384";
  let ciphertext = c.encrypt(pt);
  let plaintext = c.decrypt(ciphertext);
  t.equal(ct, ciphertext);
  t.equal(pt, plaintext);
});

test('test128dot3', (t) => {
  t.plan(2);
  // NIST FF3-AES128
  const c = new FF3Cipher("EF4359D8D580AA4F7F036D6F04FC6A94", "D8E7920AFA330A73", 10);
  const pt = "89012123456789000000789000000", ct = "48598367162252569629397416226";
  let ciphertext = c.encrypt(pt);
  let plaintext = c.decrypt(ciphertext);
  t.equal(ct, ciphertext);
  t.equal(pt, plaintext);
});

test('test128dot4', (t) => {
  t.plan(2);
  // NIST FF3-AES128
  const c = new FF3Cipher("EF4359D8D580AA4F7F036D6F04FC6A94", "0000000000000000", 10);
  const pt = "89012123456789000000789000000", ct = "34695224821734535122613701434";
  let ciphertext = c.encrypt(pt);
  let plaintext = c.decrypt(ciphertext);
  t.equal(ct, ciphertext);
  t.equal(pt, plaintext);
});

test('test128dot5', (t) => {
  t.plan(2);
  // NIST FF3-AES128
  const c = new FF3Cipher("EF4359D8D580AA4F7F036D6F04FC6A94", "9A768A92F60E12D8", 26);
  const pt = "0123456789abcdefghi", ct = "g2pk40i992fn20cjakb";
  let ciphertext = c.encrypt(pt);
  let plaintext = c.decrypt(ciphertext);
  t.equal(ct, ciphertext);
  t.equal(pt, plaintext);
});

// AES-192

test('test192dot1', (t) => {
  t.plan(2);
  // NIST FF3-AES128
  const c = new FF3Cipher("EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6", "D8E7920AFA330A73", 10);
  const pt = "890121234567890000", ct = "646965393875028755";
  let ciphertext = c.encrypt(pt);
  let plaintext = c.decrypt(ciphertext);
  t.equal(ct, ciphertext);
  t.equal(pt, plaintext);
});

test('test192dot2', (t) => {
  t.plan(2);
  // NIST FF3-AES128
  const c = new FF3Cipher("EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6", "9A768A92F60E12D8", 10);
  const pt = "890121234567890000", ct = "961610514491424446";
  let ciphertext = c.encrypt(pt);
  let plaintext = c.decrypt(ciphertext);
  t.equal(ct, ciphertext);
  t.equal(pt, plaintext);
});

test('test192dot3', (t) => {
  t.plan(2);
  // NIST FF3-AES128
  const c = new FF3Cipher("EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6", "D8E7920AFA330A73", 10);
  const pt = "89012123456789000000789000000", ct = "53048884065350204541786380807";
  let ciphertext = c.encrypt(pt);
  let plaintext = c.decrypt(ciphertext);
  t.equal(ct, ciphertext);
  t.equal(pt, plaintext);
});

test('test192dot4', (t) => {
  t.plan(2);
  // NIST FF3-AES128
  const c = new FF3Cipher("EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6", "0000000000000000", 10);
  const pt = "89012123456789000000789000000", ct = "98083802678820389295041483512";
  let ciphertext = c.encrypt(pt);
  let plaintext = c.decrypt(ciphertext);
  t.equal(ct, ciphertext);
  t.equal(pt, plaintext);
});

test('test192dot5', (t) => {
  t.plan(2);
  // NIST FF3-AES128
  const c = new FF3Cipher("EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6", "9A768A92F60E12D8", 26);
  const pt = "0123456789abcdefghi", ct = "i0ihe2jfj7a9opf9p88";
  let ciphertext = c.encrypt(pt);
  let plaintext = c.decrypt(ciphertext);
  t.equal(ct, ciphertext);
  t.equal(pt, plaintext);
});

// AES-256

test('test256dot1', (t) => {
  t.plan(2);
  // NIST FF3-AES128
  const c = new FF3Cipher("EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6ABF7158809CF4F3C", "D8E7920AFA330A73", 10);
  const pt = "890121234567890000", ct = "922011205562777495";
  let ciphertext = c.encrypt(pt);
  let plaintext = c.decrypt(ciphertext);
  t.equal(ct, ciphertext);
  t.equal(pt, plaintext);
});

test('test256dot2', (t) => {
  t.plan(2);
  // NIST FF3-AES128
  const c = new FF3Cipher("EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6ABF7158809CF4F3C", "9A768A92F60E12D8", 10);
  const pt = "890121234567890000", ct = "504149865578056140";
  let ciphertext = c.encrypt(pt);
  let plaintext = c.decrypt(ciphertext);
  t.equal(ct, ciphertext);
  t.equal(pt, plaintext);
});

test('test256dot3', (t) => {
  t.plan(2);
  // NIST FF3-AES128
  const c = new FF3Cipher("EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6ABF7158809CF4F3C", "D8E7920AFA330A73", 10);
  const pt = "89012123456789000000789000000", ct = "04344343235792599165734622699";
  let ciphertext = c.encrypt(pt);
  let plaintext = c.decrypt(ciphertext);
  t.equal(ct, ciphertext);
  t.equal(pt, plaintext);
});

test('test256dot4', (t) => {
  t.plan(2);
  // NIST FF3-AES128
  const c = new FF3Cipher("EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6ABF7158809CF4F3C", "0000000000000000", 10);
  const pt = "89012123456789000000789000000", ct = "30859239999374053872365555822";
  let ciphertext = c.encrypt(pt);
  let plaintext = c.decrypt(ciphertext);
  t.equal(ct, ciphertext);
  t.equals(pt, plaintext);
});

test('test256dot5', (t) => {
  t.plan(2);
  // NIST FF3-AES128
  const c = new FF3Cipher("EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6ABF7158809CF4F3C", "9A768A92F60E12D8", 26);
  const pt = "0123456789abcdefghi", ct = "p0b2godfja9bhb7bk38";
  let ciphertext = c.encrypt(pt);
  let plaintext = c.decrypt(ciphertext);
  t.equal(ct, ciphertext);
  t.equal(pt, plaintext);
});

test('testFF3_1', (t) => {
  t.plan(2);
  // 
  const c = new FF3Cipher("EF4359D8D580AA4F7F036D6F04FC6A94", "D8E7920AFA330A", 10);
  const pt = "890121234567890000", ct = "477064185124354662";
  let ciphertext = c.encrypt(pt);
  let plaintext = c.decrypt(ciphertext);
  t.equal(ct, ciphertext);
  t.equal(pt, plaintext);
});
