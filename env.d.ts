// vault-sink.ts's dev/prod switch reads import.meta.env.DEV, a Vite convention this package's
// consumers (bundler-based, per README.md) provide at build time. Declared locally rather than
// depending on the `vite` package just for its ambient types.
interface ImportMetaEnv {
  readonly DEV: boolean;
}
interface ImportMeta {
  readonly env: ImportMetaEnv;
}
