/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // SCAFFOLD: @finnes/sdk and @finnes/prover are consumed as raw TS source and are
  // full of intentional TODO stubs with incomplete cross-package types (e.g. the
  // snarkjs ambient shim is scoped to the prover's own tsconfig). Don't let that
  // block `next build`/dev. Canonical type checking is per-package (`npm run
  // typecheck`); revisit once the sibling packages are implemented.
  typescript: { ignoreBuildErrors: true },
  eslint: { ignoreDuringBuilds: true },
  // The sibling workspace packages ship TypeScript source (scaffold), so let
  // Next transpile them directly rather than expecting a prebuilt `dist/`.
  transpilePackages: ['@finnes/sdk', '@finnes/prover'],
  webpack: (config) => {
    // The sibling packages (and this app's lib/) use NodeNext-style `.js` import
    // specifiers that actually resolve to `.ts` source. Teach webpack to map
    // `./foo.js` -> `foo.ts`/`foo.tsx` so the raw TS source resolves.
    config.resolve.extensionAlias = {
      '.js': ['.ts', '.tsx', '.js'],
      '.mjs': ['.mts', '.mjs'],
    };
    // NOTE (trust boundary): the prover runs CLIENT-SIDE (browser WASM) inside the
    // institution trust zone. When proving is wired (lib/finnes-client.ts), snarkjs
    // will need browser fallbacks here.
    // TODO(prover): add `config.resolve.fallback = { fs: false, ... }` and ensure
    // snarkjs + the .wasm/.zkey artifacts load in the browser. Never proxy the
    // witness to a server (CLAUDE.md invariant #8).
    return config;
  },
};

export default nextConfig;
