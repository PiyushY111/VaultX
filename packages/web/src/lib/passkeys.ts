import {
  WebAuthnError,
  browserSupportsWebAuthn,
  startAuthentication,
  startRegistration,
  type AuthenticationResponseJSON,
  type PublicKeyCredentialCreationOptionsJSON,
  type PublicKeyCredentialRequestOptionsJSON,
  type RegistrationResponseJSON,
} from '@simplewebauthn/browser';

/**
 * The browser side of passkeys. The passkey never leaves the authenticator:
 * the page gets a public key (registration) or a signature over the
 * server's challenge (authentication), and passes that to the server.
 * Nothing here touches the master password or vault keys.
 */

export const passkeysSupported = (): boolean => browserSupportsWebAuthn();

/** Turns the browser's WebAuthn errors into something a person can act on. */
function describe(error: unknown, action: 'create' | 'use'): Error {
  if (
    error instanceof WebAuthnError &&
    error.code === 'ERROR_AUTHENTICATOR_PREVIOUSLY_REGISTERED'
  ) {
    return new Error('That passkey is already registered to this account.');
  }
  if (error instanceof Error && (error.name === 'NotAllowedError' || error.name === 'AbortError')) {
    return new Error(`The passkey prompt was closed or timed out. Try again to ${action} one.`);
  }
  if (error instanceof WebAuthnError && error.code === 'ERROR_INVALID_DOMAIN') {
    return new Error(
      'Passkeys aren’t available on this address. Open the vault at its usual address.',
    );
  }
  return new Error(
    `Couldn’t ${action} a passkey${error instanceof Error && error.message ? `: ${error.message}` : '.'}`,
  );
}

export async function createPasskey(
  options: PublicKeyCredentialCreationOptionsJSON,
): Promise<RegistrationResponseJSON> {
  if (!passkeysSupported()) throw new Error('This browser doesn’t support passkeys.');
  try {
    return await startRegistration({ optionsJSON: options });
  } catch (error) {
    throw describe(error, 'create');
  }
}

export async function getPasskeyAssertion(
  options: PublicKeyCredentialRequestOptionsJSON,
): Promise<AuthenticationResponseJSON> {
  if (!passkeysSupported()) throw new Error('This browser doesn’t support passkeys.');
  try {
    return await startAuthentication({ optionsJSON: options });
  } catch (error) {
    throw describe(error, 'use');
  }
}
