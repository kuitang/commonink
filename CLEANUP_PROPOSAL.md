# Documentation Cleanup Proposal

**Goal**: Remove deprecated documents, rejected alternatives, and duplicated information. Keep only what's needed to build the app.

---

## Files to DELETE

### 1. **SETUP_COMPLETE.md** ❌ DELETE
**Why**: Superseded by BUILD_SUCCESS.md
- Contains outdated SQLCipher import issues (now resolved)
- Documents the build process that's already complete
- Duplicate information in BUILD_SUCCESS.md

### 2. **IMPLEMENTATION_STATUS.md** ❌ DELETE
**Why**: Superseded by BUILD_SUCCESS.md
- Old status tracking from early setup phase
- All information consolidated into BUILD_SUCCESS.md

### 3. **DECISIONS.md** ❌ DELETE
**Why**: Superseded by DECISIONS_FINAL.md
- Contains unanswered questions (all now answered in DECISIONS_FINAL.md)
- Includes rejected alternatives (transparent proxy, Stripe, Chi, Tollbooth)
- DECISIONS_FINAL.md is the source of truth

### 4. **DECISIONS_FINAL.md** ❌ DELETE (after folding into spec.md)
**Why**: Content should be integrated into spec.md
- Architecture decisions belong in the implementation spec
- Reduces document sprawl
- spec.md becomes the single source of truth for implementation
- **Action**: Fold all decisions into spec.md before deleting

### 5. **.gitleaksignore** ❌ DELETE
**Why**: Unused (gitleaks uses .gitleaks.toml config instead)
- Created by mistake during first commit
- .gitleaks.toml is the correct config file

---

## Files to KEEP (Current Documentation)

### Implementation Guides
- ✅ **BUILD_SUCCESS.md** - Current system status and next steps
- ✅ **spec.md** - Engineering specification (will contain all decisions)
- ✅ **CLAUDE.md** - Developer guide
- ✅ **README.md** - Project overview

### Legal & Compliance
- ✅ **PRIVACY.md** - Privacy policy
- ✅ **TOS.md** - Terms of Service

### External Integration Guides
- ✅ **notes/lemonsqueezy-setup-guide.md** - Payment integration
- ✅ **notes/resend-email-setup-guide.md** - Email setup + legal compliance
- ✅ **DEPLOYMENT_ARCHITECTURE.md** - Fly.io + Tigris deployment
- ✅ **CONFORMANCE_TESTING.md** - MCP + OAuth test suites
- ✅ **CONFORMANCE_QUICK_REFERENCE.md** - Quick test commands

### Research & Background
- ✅ **notes/sqlite-encryption-research.md** - SQLite encryption analysis
- ✅ **notes/go-libraries-2026.md** - Library versions
- ✅ **notes/testing-tools.md** - External test resources
- ✅ **notes/testing-strategy.md** - Property-based testing strategy
- ✅ **notes/design.md** - Original design document (historical reference)

---

## Sections to REMOVE from Existing Files

### CONFORMANCE_TESTING.md
**Remove**: Verbose installation/setup instructions (after copying to code)
**Keep**:
- High-level overview of what conformance testing is
- Expected test categories
- Links to official conformance tools

**Rationale**: After we wire conformance tests into ci.sh and add terse instructions to CLAUDE.md, the verbose step-by-step instructions become redundant.

### CONFORMANCE_QUICK_REFERENCE.md
**Remove**: Entire file after copying commands to ci.sh
**Rationale**: Once commands are in ci.sh, this becomes unnecessary duplication

### BUILD_SUCCESS.md
**Remove**: Section "❓ 7 FOLLOW-UP QUESTIONS" (lines 122-133)
**Rationale**: All questions answered in DECISIONS_FINAL.md, no longer follow-up questions

### spec.md
**Add**: Mock testing strategy for LemonSqueezy and Resend (task #4)
**Rationale**: Needed for testing without signup/domain

---

## Summary

**Deleting**: 5 files
- SETUP_COMPLETE.md
- IMPLEMENTATION_STATUS.md
- DECISIONS.md
- DECISIONS_FINAL.md (after folding into spec.md)
- .gitleaksignore

**Folding**: DECISIONS_FINAL.md → spec.md
- Add "Architecture Decisions" section to spec.md
- Include all 7 answered questions with rationale
- Include final database schemas
- Include authentication strategy

**Keeping**: All current implementation guides, legal docs, integration guides, and research

**Trimming**: Verbose conformance instructions after copying to code

**Already Added**: Mock testing strategy in spec.md ✓

---

## Approval Request

Please review and approve:
1. ✅ Fold DECISIONS_FINAL.md into spec.md, then delete both decision files?
2. ✅ Delete 3 other obsolete files (SETUP_COMPLETE.md, IMPLEMENTATION_STATUS.md, .gitleaksignore)?
3. ✅ Remove verbose conformance instructions after copying to code?
4. ✅ Remove answered questions section from BUILD_SUCCESS.md?

Once approved, I'll execute the cleanup.
