/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // The sibling workspace packages ship TypeScript source (scaffold), so let
  // Next transpile them directly rather than expecting a prebuilt `dist/`.
  transpilePackages: ['@finnes/sdk', '@finnes/prover'],
  // NOTE (trust boundary): the prover runs CLIENT-SIDE (browser WASM) inside the
  // institution trust zone. snarkjs pulls in Node-style globals; when proving is
  // wired (see lib/finnes-client.ts), configure the webpack fallbacks here.
  // TODO(prover): add `webpack` fallbacks (fs:false, etc.) and ensure snarkjs +
  // the .wasm/.zkey artifacts load in the browser. Never proxy the witness to a
  // server (CLAUDE.md invariant #8).
};

export default nextConfig;
