// src/components/PasskeyAuth.tsx
import { mockCreationOptions, mockGetOptions } from '@/config/mockData';
import { CredentialData } from '@/types/webauthn';
import { base64UrlEncode, bufferToBase64URLString } from '@/utils/crypto';
import React, { useState } from 'react';

interface PasskeyAuthProps {
  onRegister: (credential: CredentialData) => void;
  onLogin: (credential: CredentialData) => void;
}

const PasskeyAuth: React.FC<PasskeyAuthProps> = ({ onRegister, onLogin }) => {
  const [error, setError] = useState<string | null>(null);

  const handleRegister = async () => {
    try {
      const credential = (await navigator.credentials.create({
        publicKey: mockCreationOptions,
      })) as PublicKeyCredential;

      const credentialData: CredentialData = {
        id: credential.id,
        rawId: base64UrlEncode(credential.rawId),
        type: credential.type,
        response: {
          clientDataJSON: base64UrlEncode(credential.response.clientDataJSON),
          attestationObject: base64UrlEncode(
            (credential.response as AuthenticatorAttestationResponse)
              .attestationObject
          ),
          transports:
            (
              credential.response as AuthenticatorAttestationResponse
            ).getTransports?.() || [],
        },
      };
      console.log(credential.response.attestationObject, 'credential---->');
      const publicKey = credential?.response?.getPublicKey();
      console.log(
        bufferToBase64URLString(credential?.response?.attestationObject),
        'attestationObject-bufferToBase64URLString----->'
      );
      console.log(
        bufferToBase64URLString(publicKey),
        'public-key-bufferToBase64URLString----->'
      );
      //todo: rearrange decode part
      //  console.log('Raw public key:', new Uint8Array(publicKey));
      //  const decodedWithCborWeb = CBOR.decode(publicKey);
      //  console.log('Decoded with cbor-web:', decodedWithCborWeb);
      //  const decodeResult = decodePartialCBOR(new Uint8Array(publicKey), 0);
      //  console.log('Decoded result:', JSON.stringify(decodeResult, null, 2));

      onRegister(credentialData);
    } catch (err) {
      setError(`Passkey error: ${(err as Error).message}`);
    }
  };

  const handleLogin = async () => {
    try {
      const cred = (await navigator.credentials.get({
        publicKey: mockGetOptions,
      })) as PublicKeyCredential;

      const credential: CredentialData = {
        id: cred.id,
        rawId: base64UrlEncode(cred.rawId),
        type: cred.type,
        response: {
          clientDataJSON: base64UrlEncode(cred.response.clientDataJSON),
          authenticatorData: base64UrlEncode(
            (cred.response as AuthenticatorAssertionResponse).authenticatorData
          ),
          userHandle: base64UrlEncode(
            (cred.response as AuthenticatorAssertionResponse).userHandle
          ),
          signature: base64UrlEncode(
            (cred.response as AuthenticatorAssertionResponse).signature
          ),
        },
      };

      onLogin(credential);
    } catch (err) {
      setError(`Passkey登录失败: ${(err as Error).message}`);
    }
  };

  return (
    <div className="flex flex-col space-y-4">
      <button
        onClick={handleRegister}
        className="px-4 py-2 bg-blue-500 text-white rounded hover:bg-blue-600"
      >
        Reg Passkey
      </button>
      <button
        onClick={handleLogin}
        className="px-4 py-2 bg-green-500 text-white rounded hover:bg-green-600"
      >
        Login Passkey
      </button>
      {error && <div className="text-red-500">{error}</div>}
    </div>
  );
};

export default PasskeyAuth;
