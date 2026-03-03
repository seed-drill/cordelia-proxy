/**
 * ECIES Envelope encryption tests (E1b).
 * Cross-implementation test vectors from encryption-test-vectors.md.
 */

import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import * as crypto from 'node:crypto';
import { sha256 } from '@noble/hashes/sha2.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { x25519 } from '@noble/curves/ed25519.js';
import {
  extractEd25519Seed,
  deriveX25519FromEd25519,
  envelopeEncrypt,
  envelopeDecrypt,
} from './envelope.js';

// Helper: build minimal PKCS#8 v1 DER from seed (for extractEd25519Seed test)
function seedToPkcs8(seed: Buffer): Buffer {
  const header = Buffer.from([
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
    0x04, 0x22, 0x04, 0x20,
  ]);
  return Buffer.concat([header, seed]);
}

describe('Ed25519 seed extraction', () => {
  it('extracts seed from PKCS#8 DER', () => {
    const seed = Buffer.from(
      '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60',
      'hex',
    );
    const der = seedToPkcs8(seed);
    const extracted = extractEd25519Seed(der);
    assert.equal(Buffer.from(extracted).toString('hex'), seed.toString('hex'));
  });

  it('throws on invalid DER', () => {
    assert.throws(() => extractEd25519Seed(Buffer.alloc(10)));
  });
});

describe('X25519 derivation test vectors', () => {
  const vectors = [
    {
      name: 'TV1 (RFC 8032)',
      seed: '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60',
      xPriv:
        '307c83864f2833cb427a2ef1c00a013cfdff2768d980c0a3a520f006904de94f',
      xPub: 'd85e07ec22b0ad881537c2f44d662d1a143cf830c57aca4305d85c7a90f6b62e',
    },
    {
      name: 'TV2 (all-zeros)',
      seed: '0000000000000000000000000000000000000000000000000000000000000000',
      xPriv:
        '5046adc1dba838867b2bbbfdd0c3423e58b57970b5267a90f57960924a87f156',
      xPub: '5bf55c73b82ebe22be80f3430667af570fae2556a6415e6b30d4065300aa947d',
    },
    {
      name: 'TV3 (libsodium)',
      seed: '421151a459faeade3d247115f94aedae42318124095afabe4d1451a559faedee',
      xPriv:
        '8052030376d47112be7f73ed7a019293dd12ad910b654455798b4667d73de166',
      xPub: 'f1814f0e8ff1043d8a44d25babff3cedcae6c22c3edaa48f857ae70de2baae50',
    },
    {
      name: 'TV4 (ed2curve-js)',
      seed: '9fc9b77445f8b077c29fe27fc581c52beb668ecd25f5bb2ba5777dee2a411e97',
      xPriv:
        '28e9e1d48cb0e52e437080e4a180058d7a42a07abcd05ea2ec4e6122cded8f6a',
      xPub: '26100e941bdd2103038d8dec9a1884694736f591ee814e66ae6e2e2284757136',
    },
  ];

  for (const tv of vectors) {
    it(`${tv.name}: derives correct X25519 private key`, () => {
      const seed = Buffer.from(tv.seed, 'hex');
      const { privateKey } = deriveX25519FromEd25519(seed);
      assert.equal(privateKey.toString('hex'), tv.xPriv);
    });

    it(`${tv.name}: derives correct X25519 public key`, () => {
      const seed = Buffer.from(tv.seed, 'hex');
      const { publicKey } = deriveX25519FromEd25519(seed);
      assert.equal(publicKey.toString('hex'), tv.xPub);
    });
  }
});

describe('ECDH shared secret', () => {
  it('computes matching shared secret both ways', () => {
    const seedA = Buffer.from(
      '397ceb5a8d21d74a9258c20c33fc45ab152b02cf479b2e3081285f77454cf347',
      'hex',
    );
    const seedB = Buffer.from(
      '70559b9eecdc578d5fc2ca37f9969630029f1592aff3306392ab15546c6a184a',
      'hex',
    );
    const kpA = deriveX25519FromEd25519(seedA);
    const kpB = deriveX25519FromEd25519(seedB);

    const sharedAB = x25519.scalarMult(kpA.privateKey, kpB.publicKey);
    const sharedBA = x25519.scalarMult(kpB.privateKey, kpA.publicKey);

    assert.equal(
      Buffer.from(sharedAB).toString('hex'),
      '4546babdb9482396c167af11d21953bfa49eb9f630c45de93ee4d3b9ef059576',
    );
    assert.equal(
      Buffer.from(sharedAB).toString('hex'),
      Buffer.from(sharedBA).toString('hex'),
    );
  });
});

describe('HKDF-SHA256', () => {
  it('derives correct wrapping key from test vector', () => {
    const sharedSecret = Buffer.from(
      '4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742',
      'hex',
    );
    const salt = new Uint8Array(32);
    const info = new TextEncoder().encode('cordelia-key-wrap-v1');
    const okm = hkdf(sha256, sharedSecret, salt, info, 32);
    assert.equal(
      Buffer.from(okm).toString('hex'),
      'f1f4ea6c1d40b1c6a968574803e9e21173846d7b184d522223e8a42705124f9a',
    );
  });
});

describe('Full ECIES round-trip (Section 4 test vector)', () => {
  it('encrypts with known wrapping key and verifies ciphertext', () => {
    const wrappingKey = Buffer.from(
      '8530a1a213d630eca929f96c2392cef56fb7234d2cd556d9b0cdf71b96875b63',
      'hex',
    );
    const plaintext = Buffer.from(
      'aabbccdd11223344556677889900aabbccdd11223344556677889900aabbccdd',
      'hex',
    );
    const iv = Buffer.from('000102030405060708090a0b', 'hex');

    const cipher = crypto.createCipheriv('aes-256-gcm', wrappingKey, iv, {
      authTagLength: 16,
    });
    const encrypted = Buffer.concat([
      cipher.update(plaintext),
      cipher.final(),
    ]);
    const authTag = cipher.getAuthTag();

    assert.equal(
      encrypted.toString('hex'),
      '63492d378ec7ea1aa85bee72eaad32e3fb857c2fad42b8c67bd9464c9a35318c',
    );
    assert.equal(
      authTag.toString('hex'),
      '77769938269c0d6d5e00fc13c1c9f017',
    );
  });

  it('round-trips with envelopeEncrypt/envelopeDecrypt', () => {
    const recipientSeed = Buffer.from(
      '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60',
      'hex',
    );
    const { publicKey, privateKey } = deriveX25519FromEd25519(recipientSeed);
    const plaintext = Buffer.from(
      'aabbccdd11223344556677889900aabbccdd11223344556677889900aabbccdd',
      'hex',
    );

    const envelope = envelopeEncrypt(plaintext, publicKey);
    const decrypted = envelopeDecrypt(envelope, privateKey);
    assert.equal(decrypted.toString('hex'), plaintext.toString('hex'));
  });

  it('rejects wrong recipient key', () => {
    const recipientSeed = Buffer.from(
      '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60',
      'hex',
    );
    const wrongSeed = Buffer.from(
      '421151a459faeade3d247115f94aedae42318124095afabe4d1451a559faedee',
      'hex',
    );
    const { publicKey } = deriveX25519FromEd25519(recipientSeed);
    const { privateKey: wrongPriv } = deriveX25519FromEd25519(wrongSeed);
    const plaintext = Buffer.from('secret data', 'utf-8');

    const envelope = envelopeEncrypt(plaintext, publicKey);
    assert.throws(() => envelopeDecrypt(envelope, wrongPriv));
  });

  it('rejects tampered ciphertext', () => {
    const recipientSeed = Buffer.from(
      '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60',
      'hex',
    );
    const { publicKey, privateKey } = deriveX25519FromEd25519(recipientSeed);
    const plaintext = Buffer.from('secret data', 'utf-8');

    const envelope = envelopeEncrypt(plaintext, publicKey);
    const tampered = Buffer.from(envelope.ciphertext, 'base64');
    tampered[0] ^= 0xff;
    envelope.ciphertext = tampered.toString('base64');
    assert.throws(() => envelopeDecrypt(envelope, privateKey));
  });

  it('rejects tampered authTag', () => {
    const recipientSeed = Buffer.from(
      '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60',
      'hex',
    );
    const { publicKey, privateKey } = deriveX25519FromEd25519(recipientSeed);
    const plaintext = Buffer.from('secret data', 'utf-8');

    const envelope = envelopeEncrypt(plaintext, publicKey);
    const tampered = Buffer.from(envelope.authTag, 'base64');
    tampered[0] ^= 0xff;
    envelope.authTag = tampered.toString('base64');
    assert.throws(() => envelopeDecrypt(envelope, privateKey));
  });

  it('produces unique ephemeral keys per encryption', () => {
    const recipientSeed = Buffer.from(
      '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60',
      'hex',
    );
    const { publicKey } = deriveX25519FromEd25519(recipientSeed);
    const plaintext = Buffer.from('test', 'utf-8');

    const e1 = envelopeEncrypt(plaintext, publicKey);
    const e2 = envelopeEncrypt(plaintext, publicKey);
    assert.notEqual(e1.ephemeralPublicKey, e2.ephemeralPublicKey);
    assert.notEqual(e1.iv, e2.iv);
  });

  it('handles empty plaintext', () => {
    const recipientSeed = Buffer.from(
      '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60',
      'hex',
    );
    const { publicKey, privateKey } = deriveX25519FromEd25519(recipientSeed);
    const plaintext = Buffer.alloc(0);

    const envelope = envelopeEncrypt(plaintext, publicKey);
    const decrypted = envelopeDecrypt(envelope, privateKey);
    assert.equal(decrypted.length, 0);
  });
});
