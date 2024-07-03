import { PublicKeyCredentialCreationOptionsWithChallenge, PublicKeyCredentialRequestOptionsWithChallenge } from '@/types/webauthn';
import { base64UrlDecode } from '@/utils/crypto';
import { getRpId } from '@/utils/webauthn';


export const mockCreationOptions: PublicKeyCredentialCreationOptionsWithChallenge =
  {
    challenge: base64UrlDecode('gVQ2n5FCAcksuEefCEgQRKJB_xfMF4rJMinTXSP72E8'),
    rp: {
      name: 'Passkey Example',
      id: getRpId(),
    },
    user: {
      id: base64UrlDecode('GOVsRuhMQWNoScmh_cK02QyQwTolHSUSlX5ciH242Y4'),
      name: 'Michael',
      displayName: 'Michael',
    },
    pubKeyCredParams: [
      {
        alg: -7,
        type: 'public-key',
      },
    ],
    timeout: 60000,
    attestation: 'none',
    excludeCredentials: [],
    authenticatorSelection: {
      authenticatorAttachment: 'platform',
      requireResidentKey: true,
      residentKey: 'required',
    },
    extensions: {
      credProps: true,
    },
  };

export const mockGetOptions: PublicKeyCredentialRequestOptionsWithChallenge = {
  challenge: base64UrlDecode('x1wRuShyI4k7BqYJi60kVk-clJWsPnBGgh_7z-W9QYk'),
  allowCredentials: [],
  timeout: 60000,
  rpId: getRpId(),
};
