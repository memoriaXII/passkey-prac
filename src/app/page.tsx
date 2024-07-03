'use client';

import React, { useState } from 'react';
import { ec as EC } from 'elliptic';

import * as CBOR from 'cbor-web';
import { decodePartialCBOR } from '@levischuck/tiny-cbor';

function extractPublicKey(attestationObject: ArrayBuffer): ArrayBuffer | null {
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
}

const base64UrlEncode = (buffer: ArrayBuffer): string => {
  return btoa(String.fromCharCode.apply(null, new Uint8Array(buffer)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
};

const base64UrlDecode = (base64Url: string): Uint8Array => {
  const padding = '='.repeat((4 - (base64Url.length % 4)) % 4);
  const base64 = (base64Url + padding).replace(/-/g, '+').replace(/_/g, '/');
  const rawData = atob(base64);
  return Uint8Array.from(rawData, (char) => char.charCodeAt(0));
};

// Function to get the correct RP ID
const getRpId = (): string => {
  if (typeof window !== 'undefined') {
    const hostname = window.location.hostname;
    return hostname === 'localhost' ? 'localhost' : hostname;
  }
  return 'localhost'; // Default for SSR
};

// 模拟数据
const mockCreationOptions = {
  challenge: 'gVQ2n5FCAcksuEefCEgQRKJB_xfMF4rJMinTXSP72E8',
  rp: {
    name: 'Passkey Example',
    id: getRpId(),
  },
  user: {
    id: 'GOVsRuhMQWNoScmh_cK02QyQwTolHSUSlX5ciH242Y4',
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

const mockGetOptions = {
  challenge: 'x1wRuShyI4k7BqYJi60kVk-clJWsPnBGgh_7z-W9QYk',
  allowCredentials: [],
  timeout: 60000,
  rpId: getRpId(),
};

export function bufferToBase64URLString(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let str = '';

  for (const charCode of bytes) {
    str += String.fromCharCode(charCode);
  }

  const base64String = btoa(str);

  return base64String.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

interface PasskeyAuthProps {
  onRegister: (credential: any) => void;
  onLogin: (credential: any) => void;
}

const ec = new EC('p256');
const key = ec.genKeyPair();

console.log(key, key.getPublic(), 'key---->');

var pubPoint = key.getPublic();
var x = pubPoint.getX();
var y = pubPoint.getY();

var xHex = x.toString('hex').padStart(64, '0');
var yHex = y.toString('hex').padStart(64, '0');

var fullPubKeyHex = '04' + xHex + yHex;

var fullPubKeyArray = new Uint8Array(
  fullPubKeyHex.match(/.{1,2}/g).map((byte) => parseInt(byte, 16))
);

var arrayBuffer = fullPubKeyArray.buffer;

const PasskeyAuth: React.FC<PasskeyAuthProps> = ({ onRegister, onLogin }) => {
  const [error, setError] = useState<string | null>(null);

  const handleRegister = async () => {
    try {
//mock data
      const options = { ...mockCreationOptions };

      options.challenge = base64UrlDecode(options.challenge);
      options.user.id = base64UrlDecode(options.user.id);

      // navigator.credentials.create
      const credential = (await navigator.credentials.create({
        publicKey: options as PublicKeyCredentialCreationOptions,
      })) as PublicKeyCredential;

      const credentialData = {
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
      //  console.log('Raw public key:', new Uint8Array(publicKey));
      //  const decodedWithCborWeb = CBOR.decode(publicKey);
      //  console.log('Decoded with cbor-web:', decodedWithCborWeb);
      //  const decodeResult = decodePartialCBOR(new Uint8Array(publicKey), 0);
      //  console.log('Decoded result:', JSON.stringify(decodeResult, null, 2));
      onRegister(credentialData);
    } catch (err) {
      setError('注册Passkey失败: ' + (err as Error).message);
    }
  };

  const handleLogin = async () => {
    try {
      const options = { ...mockGetOptions };

      options.challenge = base64UrlDecode(options.challenge);

      const cred = (await navigator.credentials.get({
        publicKey: options,
      })) as PublicKeyCredential;

      const credential = {
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

      // onLogin(credential);
    } catch (err) {
      setError('Passkey登录失败: ' + (err as Error).message);
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
      {error && <>{error}</>}
    </div>
  );
};

export default async function Home() {
  const handleRegister = async (credential: any) => {
    console.log('register', credential);
  };

  const handleLogin = async (credential: any) => {
    console.log('login', credential);
  };

  return (
    <main className="flex min-h-screen flex-col items-start p-24">
      <h1>Passkey view</h1>
      <PasskeyAuth onRegister={handleRegister} onLogin={handleLogin} />
    </main>
  );
}
