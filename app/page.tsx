'use client';

import { useMemo, useState } from 'react';
import { Copy, Eye, EyeOff, LockKeyhole, RefreshCw, ShieldCheck, Sparkles } from 'lucide-react';

function deriveKey(passphrase: string) {
  const bytes = new Uint8Array(32);
  const encoded = new TextEncoder().encode(passphrase);
  bytes.set(encoded.slice(0, 32));
  return bytes;
}

function toB64(bytes: Uint8Array) {
  let binary = '';
  bytes.forEach((b) => (binary += String.fromCharCode(b)));
  return btoa(binary);
}
function fromB64(value: string) {
  const binary = atob(value);
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

async function getKey(passphrase: string, usage: KeyUsage[]) {
  return crypto.subtle.importKey('raw', deriveKey(passphrase), { name: 'AES-GCM' }, false, usage);
}

async function encryptText(text: string, passphrase: string) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await getKey(passphrase, ['encrypt']);
  const data = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(text));
  const out = new Uint8Array(iv.length + data.byteLength);
  out.set(iv, 0);
  out.set(new Uint8Array(data), iv.length);
  return `PW1.${toB64(out)}`;
}

async function decryptText(payload: string, passphrase: string) {
  if (!payload.startsWith('PW1.')) throw new Error('This does not look like a PassWard encrypted value.');
  const raw = fromB64(payload.slice(4));
  const iv = raw.slice(0, 12);
  const ciphertext = raw.slice(12);
  const key = await getKey(passphrase, ['decrypt']);
  const data = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
  return new TextDecoder().decode(data);
}

export default function Home() {
  const [plain, setPlain] = useState('');
  const [encryptPass, setEncryptPass] = useState('');
  const [encrypted, setEncrypted] = useState('');
  const [decryptPass, setDecryptPass] = useState('');
  const [decrypted, setDecrypted] = useState('');
  const [encryptError, setEncryptError] = useState('');
  const [decryptError, setDecryptError] = useState('');
  const [showPlain, setShowPlain] = useState(false);
  const [showPass, setShowPass] = useState(false);
  const [busy, setBusy] = useState(false);

  const strength = useMemo(() => {
    const n = encryptPass.length;
    return n === 0 ? 'Use a long secret phrase' : n < 12 ? 'Weak — use 12+ characters' : n < 20 ? 'Good — longer is better' : 'Strong passphrase';
  }, [encryptPass]);

  async function handleEncrypt() {
    setBusy(true); setEncryptError(''); setEncrypted('');
    try {
      if (!plain || !encryptPass) throw new Error('Enter both the password/value and a secret passphrase.');
      setEncrypted(await encryptText(plain, encryptPass));
    } catch (e) { setEncryptError(e instanceof Error ? e.message : 'Encryption failed.'); }
    finally { setBusy(false); }
  }
  async function handleDecrypt() {
    setBusy(true); setDecryptError(''); setDecrypted('');
    try {
      if (!encrypted || !decryptPass) throw new Error('Enter the encrypted value and its secret passphrase.');
      setDecrypted(await decryptText(encrypted.trim(), decryptPass));
    } catch (e) { setDecryptError('Could not decrypt. Check the encrypted value and passphrase.'); }
    finally { setBusy(false); }
  }
  async function copy(value: string) { await navigator.clipboard?.writeText(value); }
  function generatePassphrase() {
    const words = ['orbit','maple','violet','rocket','cobalt','river','ember','signal','hazel','cosmos','marble','pixel'];
    const out = Array.from({ length: 4 }, () => words[crypto.getRandomValues(new Uint32Array(1))[0] % words.length]);
    setEncryptPass(`${out.join('-')}-${crypto.getRandomValues(new Uint32Array(1))[0] % 90 + 10}`);
  }

  return (
    <div className="shell">
      <header className="nav">
        <div className="brand"><span className="mark"><LockKeyhole size={17} /></span>PassWard <span className="status ok">local-first</span></div>
        <div className="status">No passwords are uploaded</div>
      </header>
      <main className="main">
        <section className="hero">
          <div className="eyebrow">Personal password vault</div>
          <h1>Turn sensitive passwords into something safe to carry.</h1>
          <p>PassWard keeps the original idea of your GitHub project—encrypt a password with a secret key, write down the encrypted result, and decrypt it later—while making the experience cleaner and browser-native.</p>
        </section>

        <section className="grid">
          <article className="card">
            <h2><ShieldCheck size={18} style={{ verticalAlign: 'text-bottom', marginRight: 7 }} /> Encrypt a password</h2>
            <div className="muted">The value is encrypted in your browser. The server never receives it.</div>
            <label className="label">Password / secret value</label>
            <div className="row">
              <input className="input" type={showPlain ? 'text' : 'password'} value={plain} onChange={(e) => setPlain(e.target.value)} placeholder="Enter the value you want to protect" />
              <button aria-label="Toggle value" className="button secondary" style={{ width: 52, marginTop: 0 }} onClick={() => setShowPlain(v => !v)}>{showPlain ? <EyeOff size={17}/> : <Eye size={17}/>}</button>
            </div>
            <label className="label">Secret passphrase</label>
            <div className="row">
              <input className="input" type={showPass ? 'text' : 'password'} value={encryptPass} onChange={(e) => setEncryptPass(e.target.value)} placeholder="A phrase only you know" />
              <button aria-label="Generate passphrase" className="button secondary" style={{ width: 52, marginTop: 0 }} onClick={generatePassphrase}><RefreshCw size={17}/></button>
              <button aria-label="Toggle passphrase" className="button secondary" style={{ width: 52, marginTop: 0 }} onClick={() => setShowPass(v => !v)}>{showPass ? <EyeOff size={17}/> : <Eye size={17}/>}</button>
            </div>
            <div className="muted" style={{ marginTop: 8 }}>{strength}</div>
            <button className="button" onClick={handleEncrypt} disabled={busy}>{busy ? 'Working…' : 'Encrypt securely'}</button>
            {encryptError && <div className="muted err" style={{ marginTop: 10 }}>{encryptError}</div>}
            {encrypted && <>
              <div className="label">Encrypted value</div>
              <div className="result">{encrypted}</div>
              <button className="button secondary" onClick={() => copy(encrypted)}><Copy size={15} style={{ verticalAlign: 'text-bottom', marginRight: 6 }} />Copy encrypted value</button>
            </>}
          </article>

          <article className="card">
            <h2><LockKeyhole size={18} style={{ verticalAlign: 'text-bottom', marginRight: 7 }} /> Decrypt a password</h2>
            <div className="muted">Paste the PassWard value and use the same secret passphrase. Nothing is stored.</div>
            <label className="label">Encrypted value</label>
            <textarea className="input" rows={5} value={encrypted} onChange={(e) => setEncrypted(e.target.value)} placeholder="PW1...." />
            <label className="label">Secret passphrase</label>
            <input className="input" type="password" value={decryptPass} onChange={(e) => setDecryptPass(e.target.value)} placeholder="The same phrase used to encrypt" />
            <button className="button" onClick={handleDecrypt} disabled={busy}>Decrypt value</button>
            {decryptError && <div className="muted err" style={{ marginTop: 10 }}>{decryptError}</div>}
            {decrypted && <>
              <div className="label">Decrypted value</div>
              <div className="result">{decrypted}</div>
              <button className="button secondary" onClick={() => copy(decrypted)}><Copy size={15} style={{ verticalAlign: 'text-bottom', marginRight: 6 }} />Copy decrypted value</button>
            </>}
          </article>
        </section>

        <div className="tip"><Sparkles size={16} style={{ verticalAlign: 'text-bottom', marginRight: 7 }} /><strong>Security note:</strong> this is a browser-local encryption utility inspired by the original PassWard project, not a production-grade synced password manager. Do not reuse an important account password as your secret passphrase, and never share the passphrase with anyone.</div>
        <div className="footer">Original concept: PassWard (Flask + Fernet). This Vercel version uses Web Crypto AES-GCM in the browser so no plaintext password or passphrase needs to be sent to a backend.</div>
      </main>
    </div>
  );
}
