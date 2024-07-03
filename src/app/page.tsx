'use client';


import React from 'react';
import PasskeyAuth from './components/PasskeyAuth';
import { CredentialData } from '@/types/webauthn';


export default function Home() {
  const handleRegister = async (credential: CredentialData) => {
    console.log('register', credential);
  };

  const handleLogin = async (credential: CredentialData) => {
    console.log('login', credential);
  };

  return (
    <main className="flex min-h-screen flex-col items-start p-24">
      <h1>Passkey view</h1>
      <PasskeyAuth onRegister={handleRegister} onLogin={handleLogin} />
    </main>
  );
}