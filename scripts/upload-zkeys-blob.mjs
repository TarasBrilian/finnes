/**
 * Upload the D=20 proving keys to Vercel Blob as PUBLIC objects (for FIN-027
 * in-browser proving on a deployed build). Public is REQUIRED: the frontend's
 * snarkjs fetches these from a static `NEXT_PUBLIC_ZKEY_URL_*` env var with no
 * auth, so a private/signed URL (which expires) cannot be used.
 *
 * Usage:
 *   npm i @vercel/blob            # one-off; not a runtime dep of the app
 *   export BLOB_READ_WRITE_TOKEN="vercel_blob_rw_..."   # from the Blob store
 *   node scripts/upload-zkeys-blob.mjs
 *
 * Prints the 3 public URLs to paste into NEXT_PUBLIC_ZKEY_URL_{SHIELD,TRANSFER,
 * UNSHIELD}. Upload the .zkey already under frontend/public/artifacts/<c>/ (the
 * Railway-ceremony keys that match the deployed VK). Secrets are never logged.
 */
import { put } from '@vercel/blob';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const token = process.env.BLOB_READ_WRITE_TOKEN;
if (!token) {
  console.error('Set BLOB_READ_WRITE_TOKEN (Vercel dashboard -> Storage -> your Blob store -> .env.local tab).');
  process.exit(1);
}

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const circuits = ['shield', 'transfer', 'unshield'];

for (const c of circuits) {
  const path = join(root, 'frontend', 'public', 'artifacts', c, `${c}.zkey`);
  const body = readFileSync(path);
  const res = await put(`${c}.zkey`, body, {
    access: 'public',          // <- the whole point: a durable, tokenless URL
    addRandomSuffix: false,     // clean pathname: <store>.public.blob.../<c>.zkey
    allowOverwrite: true,       // replace the existing (private) blob at this name
    multipart: true,            // reliable for the 105MB transfer.zkey
    contentType: 'application/octet-stream',
    token,
  });
  // res.url is the durable PUBLIC url -> goes into NEXT_PUBLIC_ZKEY_URL_<C>
  console.log(`NEXT_PUBLIC_ZKEY_URL_${c.toUpperCase()}=${res.url}`);
}
