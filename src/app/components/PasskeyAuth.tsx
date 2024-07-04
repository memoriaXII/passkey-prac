// src/components/PasskeyAuth.tsx
import { mockCreationOptions, mockGetOptions } from '@/config/mockData';
import { CredentialData } from '@/types/webauthn';
import { base64UrlEncode, bufferToBase64URLString } from '@/utils/crypto';
import React, { useEffect, useState } from 'react';
import { ec as EC } from 'elliptic';
import { COSEKEYS } from '@/helpers/cose';
import { decodeAttestationObject } from '@/helpers/decodeAttestationObject';
import { decodeCredentialPublicKey } from '@/helpers/decodeCredentialPublicKey';
import { parseAuthenticatorData } from '@/helpers/parseAuthenticatorData';
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from '@simplewebauthn/server';
import { isoUint8Array } from '@/helpers/iso';
import { cose, isoBase64URL, toHash } from '@simplewebauthn/server/helpers';
import { AsnParser, AsnSerializer } from '@peculiar/asn1-schema';
import { ECDSASigValue } from '@peculiar/asn1-ecc';

interface PasskeyAuthProps {
  onRegister: (credential: CredentialData) => void;
  onLogin: (credential: CredentialData) => void;
}

// const base64UrlEncode = (buffer: ArrayBuffer): string => {
//   return btoa(String.fromCharCode.apply(null, new Uint8Array(buffer)))
//     .replace(/\+/g, '-')
//     .replace(/\//g, '_')
//     .replace(/=/g, '');
// };

const base64UrlDecode = (base64Url: string): Uint8Array => {
  const padding = '='.repeat((4 - (base64Url.length % 4)) % 4);
  const base64 = (base64Url + padding).replace(/-/g, '+').replace(/_/g, '/');
  const rawData = atob(base64);
  return Uint8Array.from(rawData, (char) => char.charCodeAt(0));
};

interface PublicKey {
  x: string;
  y: string;
}

const PasskeyAuth: React.FC<PasskeyAuthProps> = ({ onRegister, onLogin }) => {
  const [error, setError] = useState<string | null>(null);
  const [username, setUserName] = useState('');
  const [message, setMessage] = useState('hello world');
  const [signature, setSignature] = useState('');
  const [credentialInfo, setCredientialInfo] = useState<{
    credentialId: string;
    publicKey: string;
  }>({});
  const [storedPublicKeys, setStoredPublicKeys] = useState<{
    [key: string]: PublicKey;
  }>({});

  const savePublicKey = (userId: string, publicKey: PublicKey) => {
    const updatedKeys = { ...storedPublicKeys, [userId]: publicKey };
    setStoredPublicKeys(updatedKeys);
    localStorage.setItem('passkeyPublicKeys', JSON.stringify(updatedKeys));
  };

  const handleRegister = async () => {
    try {
      // const options = await generateRegistrationOptions({
      //   ...mockCreationOptions
      // });
      const user = {
        id: isoUint8Array.fromUTF8String(username), // user EOA
        name: username, // for display only. ENS name or address. or from input
        displayName: username,
      };
      const attestationType = 'none';
      const options = await generateRegistrationOptions({
        rpName: 'Example',
        rpID: 'localhost',
        userID: user.id,
        userName: user.name,
        userDisplayName: user.displayName || user.name,
        // Prompt users for additional information about the authenticator.
        attestationType,
        // Prevent users from re-registering existing authenticators
        excludeCredentials: [],
        authenticatorSelection: {
          authenticatorAttachment: 'platform',
          requireResidentKey: true,
        },
        supportedAlgorithmIDs: [-7, -257],
      });

      const originChallenge = options.challenge;
      const publicKeyCredentialCreationOptions = {
        ...options,
      };
      // Base64URL decode some values
      publicKeyCredentialCreationOptions.user.id = base64UrlDecode(
        options.user.id
      );
      publicKeyCredentialCreationOptions.challenge = base64UrlDecode(
        options.challenge
      );

      const credential = (await navigator.credentials.create({
        publicKey: publicKeyCredentialCreationOptions,
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

      const attestationObject = base64UrlDecode(
        credentialData.response.attestationObject
      );
      const decodedAttestationObject =
        decodeAttestationObject(attestationObject);
      const authData = decodedAttestationObject.get('authData');
      const parsedAuthData = parseAuthenticatorData(authData);
      const { credentialPublicKey } = parsedAuthData;
      let cosePublicKey = decodeCredentialPublicKey(credentialPublicKey);
      const x = cosePublicKey.get(COSEKEYS.x);
      const y = cosePublicKey.get(COSEKEYS.y);

      const ec = new EC('p256');
      const key = ec.keyFromPublic({ x, y }, 'hex');

      const verification = await verifyRegistrationResponse({
        response: credentialData,
        expectedChallenge: originChallenge,
        expectedOrigin: 'http://localhost:3000', // use actual origin
        expectedRPID: 'localhost',
        requireUserVerification: false,
      });

      const { verified, registrationInfo } = verification;

      console.log('verified, registrationInfo: ', verified, registrationInfo);
      if (key.validate().result) {
        console.log(
          'Public key is valid',
          verification,
          key,
          key.validate().result
        );
        setCredientialInfo({
          credentialId: registrationInfo.credentialID,
          publicKey: base64UrlEncode(registrationInfo.credentialPublicKey),
        });
        savePublicKey(credential.id, { x, y });
        onRegister(credentialData);
      } else {
        throw new Error('Invalid public key');
      }
      // const publicKey = credential?.response?.getPublicKey();
      // console.log(
      //   bufferToBase64URLString(credential?.response?.attestationObject),
      //   'attestationObject-bufferToBase64URLString----->'
      // );
      // console.log(
      //   bufferToBase64URLString(publicKey),
      //   'public-key-bufferToBase64URLString----->'
      // );
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
      // user select corresponding credential login

      const options = await generateAuthenticationOptions({
        rpID: 'localhost',
        allowCredentials: [],
        challenge: message,
      });

      const cred = (await navigator.credentials.get({
        publicKey: {
          ...mockGetOptions,
          challenge: isoUint8Array.fromUTF8String(message),
        },
      })) as PublicKeyCredential;

      console.log(
        mockCreationOptions.challenge,
        isoUint8Array.fromUTF8String(message),
        options,
        'mockCreationOptions.challenge'
      );

      const cred_signature = base64UrlEncode(
        (cred.response as AuthenticatorAssertionResponse).signature
      );
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
          signature: cred_signature,
        },
      };
      localStorage.setItem('credential_verify', JSON.stringify(credential));
      setSignature(cred_signature);
      onLogin(credential);
    } catch (err) {
      setError(`Passkey Login Failed: ${(err as Error).message}`);
    }
  };

  function shouldRemoveLeadingZero(bytes: Uint8Array): boolean {
    return bytes[0] === 0x0 && (bytes[1] & (1 << 7)) !== 0;
  }

  function unwrapEC2Signature(signature: Uint8Array): Uint8Array {
    const parsedSignature = AsnParser.parse(signature, ECDSASigValue);
    let rBytes = new Uint8Array(parsedSignature.r);
    let sBytes = new Uint8Array(parsedSignature.s);

    if (shouldRemoveLeadingZero(rBytes)) {
      rBytes = rBytes.slice(1);
    }

    if (shouldRemoveLeadingZero(sBytes)) {
      sBytes = sBytes.slice(1);
    }

    const finalSignature = isoUint8Array.concat([rBytes, sBytes]);

    return finalSignature;
  }

  const handleVerify = async () => {
    const { publicKey } = credentialInfo;
    const credential = JSON.parse(
      localStorage.getItem('credential_verify') ?? ''
    );
    console.log('credential', credential, 'publicKey', publicKey);
    const decodedPublicKey = decodeCredentialPublicKey(
      isoBase64URL.toBuffer(publicKey)
    );
    const alg = decodedPublicKey.get(cose.COSEKEYS.alg);
    const x = decodedPublicKey.get(cose.COSEKEYS.x);
    const y = decodedPublicKey.get(cose.COSEKEYS.y);
    const WebCrypto = window.crypto;
    const _crv = 'P-256';
    const keyData: JsonWebKey = {
      kty: 'EC',
      crv: _crv,
      x: isoBase64URL.fromBuffer(x),
      y: isoBase64URL.fromBuffer(y),
      ext: false,
    };
    const keyAlgorithm: EcKeyImportParams = {
      /**
       * Note to future self: you can't use `mapCoseAlgToWebCryptoKeyAlgName()` here because some
       * leaf certs from actual devices specified an RSA SHA value for `alg` (e.g. `-257`) which
       * would then map here to `'RSASSA-PKCS1-v1_5'`. We always want `'ECDSA'` here so we'll
       * hard-code this.
       */
      name: 'ECDSA',
      namedCurve: _crv,
    };
    const webPk = await WebCrypto.subtle.importKey(
      'jwk',
      keyData,
      keyAlgorithm,
      false,
      ['verify']
    );

    console.log('alg: ', decodedPublicKey.get(cose.COSEKEYS.alg));
    console.log('crv: ', decodedPublicKey.get(cose.COSEKEYS.crv));
    console.log('kty: ', decodedPublicKey.get(cose.COSEKEYS.kty));
    console.log('e: ', decodedPublicKey.get(cose.COSEKEYS.e));
    console.log('n: ', decodedPublicKey.get(cose.COSEKEYS.n));
    console.log('x: ', decodedPublicKey.get(cose.COSEKEYS.x));
    console.log('y: ', decodedPublicKey.get(cose.COSEKEYS.y));

    const ec = new EC('p256');
    // Import public key
    const key = ec.keyFromPublic(
      {
        x: decodedPublicKey.get(cose.COSEKEYS.x),
        y: decodedPublicKey.get(cose.COSEKEYS.y),
      },
      'hex'
    );

    console.log('key: ', key);
    // const xBuffer = key.getPublic().getX().toArray();
    // const yBuffer = key.getPublic().getY().toArray();
    // const pk = new Uint8Array([...xBuffer, ...yBuffer]);

    const assertionResponse = credential.response;
    const authDataBuffer = isoBase64URL.toBuffer(
      assertionResponse.authenticatorData
    );

    const clientDataHash = await toHash(
      isoBase64URL.toBuffer(assertionResponse.clientDataJSON)
    );
    const signatureBase = isoUint8Array.concat([
      authDataBuffer,
      clientDataHash,
    ]);
    const signature = isoBase64URL.toBuffer(assertionResponse.signature);
    console.log('Signature: ', signature, unwrapEC2Signature(signature));
    console.log('verify 1: ', signature, signatureBase, key.getPublic());
    const unwrapedSignature = unwrapEC2Signature(signature);
    const verifyRes = key.verify(await toHash(signatureBase), signature);
    console.log('verifyRes: ', verifyRes);

    const verifyAlgorithm: EcdsaParams = {
      name: 'ECDSA',
      hash: { name: 'SHA-256' },
    };
    const webRes = await WebCrypto.subtle.verify(
      verifyAlgorithm,
      webPk,
      unwrapEC2Signature(signature),
      signatureBase
    );
    console.log('webRes:  ', webRes);

    if (!localStorage.getItem('credential_verify')) {
      return;
    }

    // Decode ArrayBuffers and construct an authenticator object.
    const authenticator = {
      credentialPublicKey: isoBase64URL.toBuffer(publicKey), //TODO: get publicKey from contract with address
      credentialID: isoBase64URL.toBuffer(credential.id),
      // transports: cred.transports,
    };
    const verification = await verifyAuthenticationResponse({
      response: credential,
      expectedChallenge: base64UrlEncode(isoUint8Array.fromUTF8String(message)),
      expectedOrigin: 'http://localhost:3000', // use actual origin
      expectedRPID: 'localhost',
      authenticator,
      requireUserVerification: false,
    });

    const { verified, authenticationInfo } = verification;
    console.log(
      ' verified, authenticationInfo : ',
      verified,
      authenticationInfo
    );
    if (!verified) {
      throw new Error('User verification failed.');
    }
  };

  useEffect(() => {
    const savedKeys = localStorage.getItem('passkeyPublicKeys');
    if (savedKeys) {
      setStoredPublicKeys(JSON.parse(savedKeys));
    }
  }, []);

  return (
    <div className="flex flex-col space-y-4">
      <div>
        <label htmlFor="username">Username:</label>
        <input
          type="text"
          id="username"
          value={username}
          onChange={(e) => setUserName(e.target.value)}
        />
      </div>
      <button
        onClick={handleRegister}
        className="px-4 py-2 bg-blue-500 text-white rounded hover:bg-blue-600"
      >
        Reg Passkey
      </button>
      <code>
        CredentialID: {credentialInfo.credentialId}
        <br />
        PublicKey: {credentialInfo.publicKey}
      </code>
      <button
        onClick={handleLogin}
        className="px-4 py-2 bg-green-500 text-white rounded hover:bg-green-600"
      >
        Login Passkey
      </button>
      <label htmlFor="username">Username:</label>
      <input
        type="text"
        id="username"
        value={message}
        onChange={(e) => setMessage(e.target.value)}
      />
      <code>
        Signature: {signature}
        <br />
      </code>
      <button onClick={handleVerify}>Verify with passkey</button>
      {error && <div className="text-red-500">{error}</div>}
    </div>
  );
};

export default PasskeyAuth;
