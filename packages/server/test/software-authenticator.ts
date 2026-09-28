import { createHash, generateKeyPairSync, randomBytes, sign, type KeyObject } from 'node:crypto';
import type {
  AuthenticationResponseJSON,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
} from '@simplewebauthn/server';
import { isoCBOR } from '@simplewebauthn/server/helpers';

/**
 * A minimal WebAuthn authenticator in software, for tests: ES256 keys,
 * "none" attestation, and a signature counter the test can control. It
 * builds exactly the bytes a browser and hardware authenticator would, so
 * the server's real verification code runs against it.
 */

type CborValue = Parameters<typeof isoCBOR.encode>[0];

const FLAG_USER_PRESENT = 0x01;
const FLAG_USER_VERIFIED = 0x04;
const FLAG_ATTESTED_DATA = 0x40;

const b64url = (bytes: Buffer | Uint8Array): string => Buffer.from(bytes).toString('base64url');
const sha256 = (data: Buffer | string): Buffer => createHash('sha256').update(data).digest();

export interface CeremonyOptions {
  /** The page origin the browser would report. */
  origin: string;
  /** The RP ID the authenticator hashes into authenticatorData (default: the options' rpId). */
  rpId?: string;
  /** Whether the user was verified (PIN/biometric). */
  userVerified?: boolean;
}

export class SoftwareAuthenticator {
  readonly credentialId = randomBytes(32);
  private readonly privateKey: KeyObject;
  private readonly publicJwk: { x: string; y: string };
  /** The next counter value to sign with; set it to test regressions. */
  counter = 0;

  constructor() {
    const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    this.privateKey = privateKey;
    const jwk = publicKey.export({ format: 'jwk' });
    this.publicJwk = { x: jwk.x!, y: jwk.y! };
  }

  private cosePublicKey(): Uint8Array {
    // COSE_Key for EC2 / P-256 / ES256 (RFC 9053).
    return isoCBOR.encode(
      new Map<number, number | Uint8Array>([
        [1, 2],
        [3, -7],
        [-1, 1],
        [-2, new Uint8Array(Buffer.from(this.publicJwk.x, 'base64url'))],
        [-3, new Uint8Array(Buffer.from(this.publicJwk.y, 'base64url'))],
      ]),
    );
  }

  private authData(rpId: string, flags: number, attested: boolean): Buffer {
    const counter = Buffer.alloc(4);
    counter.writeUInt32BE(this.counter);
    const parts = [sha256(rpId), Buffer.from([flags]), counter];
    if (attested) {
      const idLength = Buffer.alloc(2);
      idLength.writeUInt16BE(this.credentialId.length);
      parts.push(
        Buffer.alloc(16), // AAGUID
        idLength,
        this.credentialId,
        Buffer.from(this.cosePublicKey()),
      );
    }
    return Buffer.concat(parts);
  }

  private flags(userVerified: boolean, attested: boolean): number {
    return (
      FLAG_USER_PRESENT |
      (userVerified ? FLAG_USER_VERIFIED : 0) |
      (attested ? FLAG_ATTESTED_DATA : 0)
    );
  }

  /** navigator.credentials.create(), as JSON. */
  register(
    options: PublicKeyCredentialCreationOptionsJSON,
    { origin, rpId = options.rp.id!, userVerified = true }: CeremonyOptions,
  ): RegistrationResponseJSON {
    const clientDataJSON = Buffer.from(
      JSON.stringify({ type: 'webauthn.create', challenge: options.challenge, origin }),
    );
    const authData = this.authData(rpId, this.flags(userVerified, true), true);
    const attestation: CborValue = new Map<string, CborValue>([
      ['fmt', 'none'],
      ['attStmt', new Map<string, CborValue>()],
      ['authData', new Uint8Array(authData)],
    ]);
    const attestationObject = isoCBOR.encode(attestation);
    return {
      id: b64url(this.credentialId),
      rawId: b64url(this.credentialId),
      type: 'public-key',
      clientExtensionResults: {},
      response: {
        clientDataJSON: b64url(clientDataJSON),
        attestationObject: b64url(attestationObject),
        transports: ['internal'],
      },
    };
  }

  /** navigator.credentials.get(), as JSON. Advances the counter unless `counter` is set. */
  authenticate(
    options: PublicKeyCredentialRequestOptionsJSON,
    { origin, rpId = options.rpId!, userVerified = true }: CeremonyOptions,
    { counter }: { counter?: number } = {},
  ): AuthenticationResponseJSON {
    if (counter !== undefined) this.counter = counter;
    else if (this.counter > 0) this.counter++;
    const clientDataJSON = Buffer.from(
      JSON.stringify({ type: 'webauthn.get', challenge: options.challenge, origin }),
    );
    const authData = this.authData(rpId, this.flags(userVerified, false), false);
    const signature = sign('sha256', Buffer.concat([authData, sha256(clientDataJSON)]), {
      key: this.privateKey,
      dsaEncoding: 'der',
    });
    return {
      id: b64url(this.credentialId),
      rawId: b64url(this.credentialId),
      type: 'public-key',
      clientExtensionResults: {},
      response: {
        clientDataJSON: b64url(clientDataJSON),
        authenticatorData: b64url(authData),
        signature: b64url(signature),
      },
    };
  }
}
