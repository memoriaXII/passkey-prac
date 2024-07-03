import { useState } from 'react';
import { getPasskeyCredential } from '../../lib/passkey';

export default function PasskeyLogin() {
  const [status, setStatus] = useState('');

  const handleLogin = async () => {
    try {
      setStatus('正在获取登录选项...');
      const options = await fetch('/api/get-options').then((res) => res.json());

      setStatus('正在验证 Passkey...');
      const credential = await getPasskeyCredential(options);

      setStatus('正在登录...');
      const result = await fetch('/api/signin', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(credential),
      }).then((res) => res.json());

      setStatus(result.success ? '登录成功' : '登录失败');
    } catch (error) {
      console.error('登录错误:', error);
      setStatus('登录失败');
    }
  };

  return (
    <div>
      <h2>Passkey 登录</h2>
      <button onClick={handleLogin}>登录</button>
      <p>{status}</p>
    </div>
  );
}
