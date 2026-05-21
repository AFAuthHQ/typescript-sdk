# Vendored AFAuth conformance vectors

These files are copied verbatim from
[`AFAuthHQ/spec`](https://github.com/AFAuthHQ/spec):

- `vectors/keypair.json` (reference test-only Ed25519 keypair)
- `vectors/signatures/*.json` — §C.1, §C.2 (canonical input + reference signatures)
- `vectors/errors/*.json` — §C.5 (error envelopes)
- `vectors/replay-window/*.json` — §C.6 (replay-window sequences)

They are tracked in this repo so the SDK's conformance tests can run
without a network dependency. The upstream spec repo is the source of
truth; if these files drift from upstream, upstream wins.

## Re-syncing

When the spec repo updates its vectors, re-vendor:

```bash
# from typescript-sdk repo root, with AFAuthHQ/spec checked out at ../spec
cp ../spec/vectors/keypair.json                vendor/spec-vectors/keypair.json
cp ../spec/vectors/signatures/*.json           vendor/spec-vectors/signatures/
cp ../spec/vectors/errors/*.json               vendor/spec-vectors/errors/
cp ../spec/vectors/replay-window/*.json        vendor/spec-vectors/replay-window/
```

Then re-run `pnpm test` and commit.

## Provenance

- Source: `https://github.com/AFAuthHQ/spec`
- Spec sections: Appendix C.1, C.2, C.5, C.6
- License: Apache-2.0 (per `LICENSE-CODE` in the spec repo)
