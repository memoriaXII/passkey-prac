import { base64UrlEncode, base64UrlDecode } from './utils';

export async function createPasskey(options) {
  const publicKeyCredentialCreationOptions = {
    ...options,
    challenge: base64UrlDecode(options.challenge),
    user: {
      ...options.user,
      id: base64UrlDecode(options.user.id),
    },
  };

  const credential = await navigator.credentials.create({
    publicKey: publicKeyCredentialCreationOptions,
  });

  return {
    id: credential.id,
    rawId: base64UrlEncode(credential.rawId),
    type: credential.type,
    response: {
      clientDataJSON: base64UrlEncode(credential.response.clientDataJSON),
      attestationObject: base64UrlEncode(credential.response.attestationObject),
      transports: credential.response.getTransports
        ? credential.response.getTransports()
        : [],
    },
    authenticatorAttachment: credential.authenticatorAttachment,
  };
}

export async function getPasskeyCredential(options) {
  const publicKeyCredentialRequestOptions = {
    ...options,
    challenge: base64UrlDecode(options.challenge),
  };

  const credential = await navigator.credentials.get({
    publicKey: publicKeyCredentialRequestOptions,
  });

  return {
    id: credential.id,
    rawId: base64UrlEncode(credential.rawId),
    type: credential.type,
    response: {
      clientDataJSON: base64UrlEncode(credential.response.clientDataJSON),
      authenticatorData: base64UrlEncode(credential.response.authenticatorData),
      signature: base64UrlEncode(credential.response.signature),
      userHandle: credential.response.userHandle
        ? base64UrlEncode(credential.response.userHandle)
        : null,
    },
  };
}

export function isPasskeySupported() {
  return typeof window !== 'undefined'
    ? navigator.userAgent.toUpperCase().indexOf('MAC') >= 0
    : false;;
}
