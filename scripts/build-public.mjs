import { copyFile, mkdir, readFile, unlink, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { deploymentIdentity } from './deployment-identity.mjs';

const root = resolve(import.meta.dirname, '..');
const output = resolve(root, 'public', 'data.json');
const publicDirectory = resolve(root, 'public');
const config = JSON.parse(await readFile(resolve(root, 'aleph.config.json'), 'utf8'));
if (config.step !== 3) {
  throw new Error('3단계 빌드에는 aleph.config.json의 step이 3이어야 합니다.');
}
await mkdir(resolve(root, 'public'), { recursive: true });
await unlink(output).catch(error => {
  if (error.code !== 'ENOENT') throw error;
});
const vendorDirectory = resolve(publicDirectory, 'vendor');
await mkdir(vendorDirectory, { recursive: true });
await copyFile(
  resolve(root, 'node_modules', '@supabase', 'supabase-js', 'dist', 'umd', 'supabase.js'),
  resolve(vendorDirectory, 'supabase.js'),
);
await copyFile(resolve(root, 'src', 'auth-controller.mjs'), resolve(publicDirectory, 'auth-controller.mjs'));
await copyFile(resolve(root, 'src', 'auth-browser.mjs'), resolve(publicDirectory, 'auth-browser.mjs'));

let publicAuthConfig = null;
const supabaseUrl = process.env.SUPABASE_URL;
const publishableKey = process.env.SUPABASE_PUBLISHABLE_KEY;
if (supabaseUrl && publishableKey) {
  try {
    const url = new URL(supabaseUrl);
    if (url.protocol !== 'https:' || url.username || url.password || url.pathname !== '/'
        || url.search || url.hash || !publishableKey.startsWith('sb_publishable_')) {
      throw new Error();
    }
    publicAuthConfig = { supabaseUrl: url.origin, publishableKey };
  } catch {
    throw new Error('Supabase 브라우저 설정은 HTTPS Project URL과 Publishable Key가 필요합니다.');
  }
} else {
  console.log('Supabase Publishable Key가 없어 로그인 설정은 비활성 상태로 빌드합니다.');
}
await writeFile(resolve(publicDirectory, 'supabase-config.js'),
  `window.BYTE_BACK_SUPABASE_CONFIG = ${JSON.stringify(publicAuthConfig)};\n`, 'utf8');
console.log('공개 data.json을 생성하지 않았습니다.');
if (!process.argv.includes('--local')) {
  const identity = deploymentIdentity(process.env, config);
  await writeFile(resolve(root, 'public', 'aleph.json'),
    `${JSON.stringify(identity, null, 2)}\n`, 'utf8');
  console.log('배포 저장소·커밋·주소를 public/aleph.json에 기록했습니다.');
}
