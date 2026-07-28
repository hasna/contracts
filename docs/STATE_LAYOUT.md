# State layout

`@hasna/contracts` is an execution-free library and currently owns no
persistent user state. Installing or running its validation commands does not
create a home directory.

If the package gains user-level state in the future, its only canonical global
root is:

```text
~/.hasna/contracts
```

The legacy roots `~/.contracts` and `~/.open-contracts` are not operational read
paths. The package never copies, moves, rewrites, or deletes them. There is no
automatic migration because the current package has no global store or
installer-owned data to migrate. Any files found at those paths must be audited
before manual removal rather than treated as `@hasna/contracts` data.

## Intentional project-local paths

These paths remain relative to the consuming project or target repository. They
must not be redirected into `~/.hasna/contracts`.

| Path | Owner and purpose |
| --- | --- |
| `.hasna/project/**` | Project metadata defined by the project-manifest schemas. `@hasna/contracts` validates the layout; `open-projects` owns reading and writing it. |
| `src/generated/storage-kit/.storage-kit-manifest.json` | Deterministic `vendor-kit` output tracked in the target repository alongside the generated storage kit. |
| `.hasna/loops/runs/**` | OpenLoops run artifacts described by the integration contract. They are owned by OpenLoops, not by `@hasna/contracts`. |

Other dotdir references are declarations or negative fixtures, not Contracts
state. In particular, `.codewith` and other `.hasna/<app>` paths in the secure
local-store policy belong to their named packages, while `.hasna/cloud` appears
in the no-cloud scanner as a forbidden legacy runtime path.

The repository ignores `.hasna/` so local project metadata is not accidentally
committed. The generated storage-kit manifest is outside that ignored directory
and is intentionally checked into each target repository.
