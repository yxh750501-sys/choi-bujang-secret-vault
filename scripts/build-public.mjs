import { copyFile, mkdir, readFile, unlink, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { deploymentIdentity } from './deployment-identity.mjs';

const root = resolve(import.meta.dirname, '..');
const output = resolve(root, 'public', 'data.json');
const publicDirectory = resolve(root, 'public');
const obsoleteSupabaseAssets = [
  resolve(publicDirectory, 'supabase-config.js'),
  resolve(publicDirectory, 'vendor', 'supabase.js'),
];
const config = JSON.parse(await readFile(resolve(root, 'aleph.config.json'), 'utf8'));
if (![4, 5, 6, 7, 8, 9].includes(config.step)) {
  throw new Error('4~9단계 빌드에는 aleph.config.json의 step이 4, 5, 6, 7, 8 또는 9이어야 합니다.');
}
await mkdir(resolve(root, 'public'), { recursive: true });
await unlink(output).catch(error => {
  if (error.code !== 'ENOENT') throw error;
});
await Promise.all(obsoleteSupabaseAssets.map(path => unlink(path).catch(error => {
  if (error.code !== 'ENOENT') throw error;
})));
await copyFile(resolve(root, 'src', 'auth-controller.mjs'), resolve(publicDirectory, 'auth-controller.mjs'));
await copyFile(resolve(root, 'src', 'auth-browser.mjs'), resolve(publicDirectory, 'auth-browser.mjs'));

console.log('공개 data.json을 생성하지 않았습니다.');
if (!process.argv.includes('--local')) {
  const identity = deploymentIdentity(process.env, config);
  await writeFile(resolve(root, 'public', 'aleph.json'),
    `${JSON.stringify(identity, null, 2)}\n`, 'utf8');
  console.log('배포 저장소·커밋·주소를 public/aleph.json에 기록했습니다.');
}
