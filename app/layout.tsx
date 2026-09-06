import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'PassWard — Personal Password Vault',
  description: 'A local-first password encryption and decryption vault inspired by PassWard.',
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="en"><body>{children}</body></html>;
}
