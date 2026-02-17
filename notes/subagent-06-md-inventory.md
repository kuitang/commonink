# Subagent Note 06 - Markdown Inventory and Deletion Candidates (Working)

## Runtime-required markdown (do not delete)
- `static/src/privacy.md`
- `static/src/tos.md`
- `static/src/about.md`
- `static/src/api-docs.md`

These are served dynamically by `internal/web/static_handler.go`.

## Candidate obsolete top-level docs (likely delete after consolidation)
- `BUILD_SUCCESS.md`
- `DEPLOYMENT_ARCHITECTURE.md`
- `DESIGN.md`
- `MILESTONE1_PLAN.md`
- `MILESTONE1_STATUS.md`
- `MILESTONE2_PLAN.md`
- `MILESTONE3_PLAN.md`
- `MILESTONE3_5_PLAN.md`
- `MILESTONE4_PLAN.md`
- `MILESTONE5_PLAN.md`
- `MILESTONE6_PLAN.md`
- `PRIVACY.md` (dup of static runtime doc source)
- `TOS.md` (dup of static runtime doc source)
- `README.md` (replace with compact pointer to docs/)
- `spec.md` (replace by `docs/SPEC.md`)

## Candidate obsolete notes/ and research docs (replace with new consolidated docs)
- Existing legacy files under `notes/` except newly generated subagent notes for this task.

## Internal package docs candidates
- `internal/db/README.md`
- `internal/db/IMPLEMENTATION.md`

Need to check whether scripts/tests hard-fail on these file paths before deleting.
