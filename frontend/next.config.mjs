/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // FIN-023: type errors now BLOCK the build (no `ignoreBuildErrors`). The
  // snarkjs ambient shim (prover/src/snarkjs.d.ts) is included by this app's
  // tsconfig, so the consumed sibling TS source typechecks cleanly here. ESLint
  // is not configured in this app; `next build` skips lint, and canonical type
  // checking is `npm run typecheck` (sdk/prover) + `tsc --noEmit` (frontend).
  // The sibling workspace packages ship TypeScript source (scaffold), so let
  // Next transpile them directly rather than expecting a prebuilt `dist/`.
  transpilePackages: ['@finnes/sdk', '@finnes/prover'],
  webpack: (config, { isServer }) => {
    // The sibling packages (and this app's lib/) use NodeNext-style `.js` import
    // specifiers that actually resolve to `.ts` source. Teach webpack to map
    // `./foo.js` -> `foo.ts`/`foo.tsx` so the raw TS source resolves.
    config.resolve.extensionAlias = {
      '.js': ['.ts', '.tsx', '.js'],
      '.mjs': ['.mts', '.mjs'],
    };
    // Trust boundary: the prover runs CLIENT-SIDE (browser WASM) inside the
    // institution trust zone (FIN-027, option 2). snarkjs references Node builtins
    // that don't exist in the browser; stub them so the client bundle builds and
    // snarkjs takes its browser code path (fetches the .wasm/.zkey over HTTP and
    // proves with WebAssembly). The witness never leaves this tab (invariant #8).
    if (!isServer) {
      config.resolve.fallback = {
        ...config.resolve.fallback,
        fs: false,
        readline: false,
        path: false,
        os: false,
        crypto: false,
        stream: false,
        constants: false,
      };
    }
    return config;
  },
};

export default nextConfig;
