import { useState } from 'react';
import { createPasskey } from '../../lib/passkey';

export default function PasskeyRegister() {
  const [status, setStatus] = useState('');

  const handleRegister = async () => {
    try {
      setStatus('正在获取注册选项...');
      const options = await fetch('/api/create-options').then((res) =>
        res.json()
      );

      setStatus('正在创建 Passkey...');
      const credential = await createPasskey(options);

      setStatus('正在注册 Passkey...');
      const result = await fetch('/api/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(credential),
      }).then((res) => res.json());

      setStatus(result.success ? '注册成功' : '注册失败');
    } catch (error) {
      console.error('注册错误:', error);
      setStatus('注册失败');
    }
  };

  return (
    <div>
      <h2>注册 Passkey</h2>
      <button onClick={handleRegister}>注册</button>
      <p>{status}</p>
    </div>
  );
}
