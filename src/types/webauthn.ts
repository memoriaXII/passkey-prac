export interface PublicKeyCredentialCreationOptionsWithChallenge
  extends PublicKeyCredentialCreationOptions {
  challenge: ArrayBuffer;
}

export interface PublicKeyCredentialRequestOptionsWithChallenge
  extends PublicKeyCredentialRequestOptions {
  challenge: ArrayBuffer;
}

export interface CredentialData {
  id: string;
  rawId: string;
  type: string;
  response: {
    clientDataJSON: string;
    attestationObject?: string;
    authenticatorData?: string;
    userHandle?: string;
    signature?: string;
    transports?: AuthenticatorTransport[];
  };
}
