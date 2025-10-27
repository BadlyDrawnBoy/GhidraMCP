# Release checklist

This repository ships the deterministic Ghidra MCP bridge as a single package that combines
Python code, JSON schemas, and Ghidra plugin artefacts. Follow the steps below whenever you cut
an official release.

## 1. Pre-flight

- Ensure the working tree is clean and rebased on `main`.
- Confirm the MCP bridge still runs locally via the instructions in the README.
- Bump any version strings embedded in artefacts (if applicable).

## 2. Schema/version sanity

- Check `bridge/api/schemas/` for new or modified schemas.
- If a schema shape changes, bump the filename suffix (`.v1.json` → `.v2.json`) and update
  call sites/tests accordingly.
- Verify the schema `$id` matches the filename and version.

## 3. Tests & quality gates

- Run `pytest` (all suites) and ensure they pass.
- Re-run the deterministic golden tests if snapshots changed (`UPDATE_GOLDEN_SNAPSHOTS=1 pytest ...`).
- Lint or type-check if new tooling is introduced.

## 4. Documentation

- Update `docs/CHANGELOG.md` with a new section describing noteworthy changes.
- Make sure the README and `.env.sample` reflect new flags, schemas, or features.
- Capture any new operational notes (limits, flags) inside `docs/`.

## 5. Build artefacts

- Generate the Ghidra plugin: `mvn clean package assembly:single`.
- Archive the plugin ZIP together with the Python source (or wheel) you intend to publish.
- If distributing via PyPI/internal index, build the Python package now.

## 6. Tag & publish

- Tag the release (`git tag -a vX.Y.Z -m "Release vX.Y.Z"`).
- Push the tag and open a GitHub release draft.
- Attach the plugin ZIP + Python distribution artefacts.
- Paste the matching changelog entry into the release notes.

## 7. Rollback plan

- If issues arise, revert to the previous tag and redeploy the last known-good artefacts.
- Communicate the rollback in the changelog and release notes.
- File follow-up issues for any regressions discovered post-release.
