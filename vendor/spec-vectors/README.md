# Vendored AFAuth conformance vectors

These files are copied verbatim from
[`AFAuthHQ/spec`](https://github.com/AFAuthHQ/spec) — specifically
`vectors/keypair.json` and `vectors/signatures/*.json`.

They are tracked in this repo so the SDK's conformance tests can run
without a network dependency. The upstream spec repo is the source of
truth; if these files drift from upstream, upstream wins.

## Re-syncing

When the spec repo updates its vectors, re-vendor:

```bash
# from typescript-sdk repo root, with AFAuthHQ/spec checked out at ../spec
cp ../spec/vectors/keypair.json vendor/spec-vectors/keypair.json
cp ../spec/vectors/signatures/*.json vendor/spec-vectors/signatures/
node harness-check.mjs   # optional: run the upstream harness against the vendored copy
```

Then re-run `pnpm test` and commit.

## Provenance

- Source: `https://github.com/AFAuthHQ/spec`
- Spec section: Appendix C.1 (canonical input), C.2 (reference signatures)
- License: Apache-2.0 (per `LICENSE-CODE` in the spec repo)
