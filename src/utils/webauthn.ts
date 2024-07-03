import * as CBOR from 'cbor-web';
import {
  PublicKeyCredentialCreationOptionsWithChallenge,
  PublicKeyCredentialRequestOptionsWithChallenge,
} from '../types/webauthn';

export const extractPublicKey = (
  attestationObject: ArrayBuffer
): ArrayBuffer | null => {
  const attestationCBOR = CBOR.decode(attestationObject);
  const authData = attestationCBOR.authData;

  if (!authData || authData.byteLength < 37) {
    console.error('Invalid authData');
    return null;
  }

  const dataView = new DataView(authData.buffer);
  const publicKeyLength = dataView.getUint16(53);

  if (authData.byteLength < 55 + publicKeyLength) {
    console.error('AuthData too short to contain public key');
    return null;
  }

  return authData.slice(55, 55 + publicKeyLength);
};

export const getRpId = (): string => {
  if (typeof window !== 'undefined') {
    const hostname = window.location.hostname;
    return hostname === 'localhost' ? 'localhost' : hostname;
  }
  return 'localhost'; // Default for SSR
};
