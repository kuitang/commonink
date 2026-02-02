# SQLite Encryption Research: Pure Go vs CGO-Based Solutions

**Date:** 2026-02-02
**Use Case:** Local-first notes application with encryption at rest

---

## Executive Summary

**Critical Finding:** Pure Go SQLite implementations currently **do not support SQLCipher-level encryption**. All production-grade SQLite encryption solutions require CGO.

**Recommendation for Notes App:**
1. **For encryption at rest:** Use `mattn/go-sqlite3` + SQLCipher (CGO required)
2. **For CGO-free deployment:** Use `modernc.org/sqlite` + application-level encryption
3. **Emerging option:** Consider `ncruces/go-sqlite3` with built-in Adiantum/XTS encryption (pure Go via Wasm)

---

## Decision Matrix

| Library | CGO | Encryption | Performance | Production Ready | Cross-Compile |
|---------|-----|------------|-------------|------------------|---------------|
| **mattn/go-sqlite3** | ✅ Yes | ✅ SQLCipher | ⭐⭐⭐⭐⭐ Best | ✅ Battle-tested | ❌ Complex |
| **modernc.org/sqlite** | ❌ No | ❌ None | ⭐⭐⭐ Good (50-75% of CGO) | ✅ Stable (2+ years) | ✅ Easy |
| **zombiezen.com/go/sqlite** | ❌ No | ❌ None | ⭐⭐⭐ Good (uses modernc) | ✅ Stable | ✅ Easy |
| **crawshaw.io/sqlite** | ✅ Yes | ⚠️ External | ⭐⭐⭐⭐⭐ Best | ✅ Production | ❌ Complex |
| **ncruces/go-sqlite3** | ❌ No | ✅ Adiantum/XTS | ⭐⭐⭐⭐ Very Good | ⚠️ Newer | ✅ Easy |

---

## Detailed Library Analysis

### 1. mattn/go-sqlite3 (CGO)

**Overview:**
- Most popular Go SQLite driver (standard CGO wrapper)
- Direct C bindings to SQLite

**Encryption Support:**
- ✅ Full SQLCipher integration available via forks:
  - `github.com/mutecomm/go-sqlcipher` - Self-contained with AES-256
  - `github.com/CovenantSQL/go-sqlite3-encrypt` - go-sqlite3 + sqlcipher
- ✅ Industry-standard 256-bit AES encryption
- ✅ PBKDF2 key derivation with configurable iterations
- ✅ Per-page HMAC for tamper detection

**Performance:**
- **Baseline:** 1531ms insert / 1018ms query (simple benchmark)
- **Encryption overhead:** 5-15% in optimized cases, up to 50% worst case
- **Best-in-class** for raw SQLite performance

**Production Usage:**
- ✅ Battle-tested across thousands of projects
- ✅ Used by major Go applications
- ✅ Complete feature parity with C SQLite

**Limitations:**
- ❌ Requires CGO (complicates cross-compilation)
- ❌ Need C compiler on build system
- ❌ Cannot use Go race detector across CGO boundary
- ❌ Static linking challenges

**Cross-Compilation:**
- Complex - requires OS-specific headers and C toolchains
- Tools like `xgo` needed for multi-platform builds
- Build process: `go build && scp` becomes multi-stage

**Recommendation:** ⭐⭐⭐⭐⭐ **Best choice if encryption is required and CGO is acceptable**

---

### 2. modernc.org/sqlite (Pure Go)

**Overview:**
- Automatic C-to-Go translation of official SQLite source
- 100% pure Go implementation
- Imported by 2,562+ packages (as of Jan 2026)

**Encryption Support:**
- ❌ **No built-in encryption**
- ❌ No SQLCipher compatibility
- ⚠️ Must implement application-level encryption separately

**Performance:**
- **Benchmarks:** 5288ms insert / 760ms query (simple test)
- **2x slower on INSERTs** vs mattn/go-sqlite3
- **10-100% slower on SELECTs** vs mattn/go-sqlite3
- **~50-75% of CGO performance** overall
- ✅ Good enough for most applications

**Production Usage:**
- ✅ Stable - 2+ years of CI testing (Gogs project)
- ✅ Sponsored by Schleibinger Geräte (commercial use)
- ✅ No known critical issues
- ⚠️ Limited public production case studies

**Limitations:**
- ❌ **No encryption support**
- ⚠️ Single-writer limitation (standard SQLite constraint)
- ⚠️ Must use `DB.SetMaxOpenConns(1)` to avoid SQLITE_BUSY
- ⚠️ Version compatibility: must match `modernc.org/libc` versions

**Cross-Compilation:**
- ✅ **Trivial** - pure Go compiles anywhere
- ✅ `CGO_ENABLED=0 go build` works perfectly
- ✅ No C toolchain needed
- ✅ Race detector works

**Recommendation:** ⭐⭐⭐⭐ **Best for CGO-free deployments without encryption**

---

### 3. zombiezen.com/go/sqlite (Pure Go)

**Overview:**
- Fork of crawshaw.io/sqlite
- Uses modernc.org/sqlite under the hood
- Designed as drop-in replacement for crawshaw

**Encryption Support:**
- ❌ **No SQLCipher support**
- ❌ No built-in encryption
- Extensions: session, FTS5, RTree, JSON1, GeoPoly (no encryption)

**Performance:**
- Similar to modernc.org/sqlite (same underlying implementation)
- ~50-75% of CGO performance
- **6x slower than crawshaw** (crawshaw comparison)

**Production Usage:**
- ✅ Reached 1.0 (Dec 2023)
- ✅ Actively maintained
- ✅ Good API design with better ergonomics than crawshaw

**Key Features:**
- ✅ Streaming blob I/O (incremental I/O)
- ✅ User-defined functions
- ✅ Schema migration utilities
- ❌ Deliberately **no database/sql driver** (use modernc directly if needed)

**Limitations:**
- ❌ **No encryption**
- ⚠️ Performance trade-off vs CGO
- ⚠️ Higher memory usage than mattn

**Cross-Compilation:**
- ✅ CGO-free (full benefits)

**Recommendation:** ⭐⭐⭐ **Good API but no clear advantage over modernc.org/sqlite for notes app**

---

### 4. crawshaw.io/sqlite (CGO)

**Overview:**
- Low-level CGO interface to SQLite
- Connection pooling with unlock-notify API
- Used as basis for zombiezen fork

**Encryption Support:**
- ⚠️ No built-in encryption
- ⚠️ Can integrate SQLite encryption extensions manually
- Limited documentation on encryption setup

**Performance:**
- ⭐⭐⭐⭐⭐ **Best CGO performance**
- **6x faster** than modernc.org/sqlite
- Multi-threaded connection pools

**Production Usage:**
- ✅ Used in iOS apps (per author's blog)
- ✅ Production-ready
- ✅ Lower-level control than mattn

**Limitations:**
- ❌ Requires CGO
- ⚠️ Less encryption documentation than mattn
- ⚠️ Smaller ecosystem than mattn

**Cross-Compilation:**
- ❌ Complex (CGO challenges)

**Recommendation:** ⭐⭐⭐ **Only if you need low-level CGO performance without encryption**

---

### 5. ncruces/go-sqlite3 (Pure Go via Wasm)

**Overview:**
- CGO-free using Wasm build of SQLite + wazero runtime
- **Innovative approach:** Wasm sandboxing without CGO
- Updated Jan 24, 2026 (very recent)

**Encryption Support:**
- ✅ **Built-in encryption VFS implementations:**
  - `vfs/adiantum` - Adiantum tweakable encryption (4KB blocks)
  - `vfs/xts` - XTS encryption at rest
- ✅ Pure Go encryption (no SQLCipher dependency)
- ⚠️ Different encryption than SQLCipher (not compatible)

**Performance:**
- ⭐⭐⭐⭐ Very good for CGO-free solution
- ⚠️ Higher memory usage (Wasm sandbox per connection)
- ⚠️ Wasm runtime overhead (but improving)

**Production Usage:**
- ⚠️ **Newer project** (less battle-tested than others)
- ✅ Actively maintained
- ✅ Provides database/sql driver
- ⚠️ Limited production case studies

**Key Features:**
- ✅ Pure Go encryption support (unique among CGO-free options)
- ✅ VFS extension support
- ✅ database/sql compatible

**Limitations:**
- ⚠️ Not SQLCipher-compatible (different encryption scheme)
- ⚠️ Memory overhead from Wasm sandboxing
- ⚠️ Newer = less proven

**Cross-Compilation:**
- ✅ CGO-free benefits

**Recommendation:** ⭐⭐⭐⭐ **Most promising CGO-free encryption option, but verify production readiness**

---

## Encryption Deep Dive

### SQLCipher Encryption (CGO only)

**Algorithm:** AES-256 in CBC mode (configurable)
**Key Derivation:** PBKDF2 with 256,000+ iterations
**Features:**
- Per-page encryption
- Per-page HMAC for tamper detection
- Secure delete (overwrites deleted pages)
- FIPS-compliant options available

**Performance Impact:**
- **Best case:** 5-15% overhead (well-optimized apps)
- **Worst case:** ~50% overhead (poor cache hit rates)
- **Key opening cost:** High (PBKDF2 stretching) but only once
- **Caching:** Queries from cache use pre-decrypted pages (no overhead)

**Production Considerations:**
- ✅ Industry standard (used since 2006)
- ✅ Used by major apps (WhatsApp, Signal, etc.)
- ✅ Regular security audits
- ✅ Commercial support available

---

### Application-Level Encryption (Pure Go option)

**Approach:** Encrypt sensitive fields before INSERT, decrypt after SELECT

**Go Libraries:**
- `crypto/aes` - AES-GCM (recommended)
- `golang.org/x/crypto/chacha20poly1305` - ChaCha20-Poly1305 (recommended)
- Both are pure Go, no CGO needed

**Implementation Pattern:**
```go
// Encrypt before storing
encryptedContent := encryptAES_GCM(noteContent, key)
db.Exec("INSERT INTO notes (content) VALUES (?)", encryptedContent)

// Decrypt after reading
db.QueryRow("SELECT content FROM notes WHERE id=?", id).Scan(&encrypted)
plaintext := decryptAES_GCM(encrypted, key)
```

**Pros:**
- ✅ Pure Go - no CGO
- ✅ Selective encryption (only sensitive fields)
- ✅ Cross-platform compilation simple
- ✅ Full control over encryption scheme

**Cons:**
- ❌ Cannot query encrypted fields (no WHERE on encrypted columns)
- ❌ Cannot index encrypted content
- ❌ More application code complexity
- ❌ Metadata still visible (table structure, row counts)
- ❌ No page-level protection

**Performance:**
- Minimal overhead for encryption/decryption operations
- No database I/O overhead
- Better for read-heavy workloads with selective encryption

**Security Comparison:**
| Feature | SQLCipher | App-Level |
|---------|-----------|-----------|
| Full database encryption | ✅ | ❌ |
| Metadata protection | ✅ | ❌ |
| File-level encryption | ✅ | ❌ |
| Selective field encryption | ❌ | ✅ |
| Queryable encrypted fields | ❌ | ❌ |
| Page integrity checks | ✅ | ❌ |

---

### ncruces Adiantum/XTS Encryption (Pure Go)

**Adiantum:**
- Tweakable, length-preserving encryption
- Designed for devices without AES hardware acceleration
- 4KB block encryption (matches SQLite page size)

**XTS Mode:**
- IEEE standard for block device encryption
- Used in disk encryption (BitLocker, FileVault)

**Pros:**
- ✅ Pure Go implementation
- ✅ VFS-level encryption (transparent to application)
- ✅ No CGO required

**Cons:**
- ⚠️ Not SQLCipher-compatible
- ⚠️ Cannot open encrypted databases created by other tools
- ⚠️ Less proven than SQLCipher

---

## Performance Comparison Summary

### Raw SQLite Operations (no encryption)

| Library | Simple Insert | Simple Query | Complex Insert | Complex Query |
|---------|--------------|--------------|----------------|---------------|
| mattn/go-sqlite3 | 1531ms | 1018ms | 843ms | 1187ms |
| modernc.org/sqlite | 5288ms | 760ms | 2909ms | 1100ms |
| crawshaw.io/sqlite | ~1400ms | ~900ms | ~800ms | ~1100ms |

**Takeaway:** CGO is 2-3x faster on writes, comparable on reads

### With Encryption

| Solution | Overhead | Notes |
|----------|----------|-------|
| SQLCipher (mattn) | 5-15% optimized, up to 50% worst case | Depends on cache hit rate |
| App-level (modernc) | <5% crypto overhead | No I/O overhead, but 2x baseline I/O cost |
| ncruces Adiantum | Unknown | Likely 10-20% (VFS overhead) |

---

## Production Readiness Assessment

### Battle-Tested (5+ years)
- ✅ mattn/go-sqlite3 + SQLCipher
- ✅ crawshaw.io/sqlite

### Proven Stable (2-3 years)
- ✅ modernc.org/sqlite
- ✅ zombiezen.com/go/sqlite

### Emerging (< 2 years)
- ⚠️ ncruces/go-sqlite3

---

## CGO Trade-offs Analysis

### Problems with CGO

**Cross-Compilation Complexity:**
- Requires OS-specific headers and libraries
- Need C toolchain for each target platform
- Tools like `xgo` add significant build complexity

**Development Experience:**
- Cannot use Go race detector across CGO boundary
- Separate build environments for different OSes
- `go build && scp` becomes multi-stage Docker builds

**Static Linking:**
- Dynamic library dependencies complicate deployment
- Binary portability issues

**Quote from Dave Cheney:** *"cgo is not Go"* - highlighting the ecosystem split

### Benefits of Pure Go

**Deployment:**
- Single static binary
- `CGO_ENABLED=0 go build` works everywhere
- No runtime dependencies

**Development:**
- Full Go tooling support (race detector, fuzzing, coverage)
- Consistent cross-platform builds
- Faster compile times

**Maintenance:**
- No C dependency upgrades
- No platform-specific bugs from C libraries

---

## Recommendations by Use Case

### Use Case 1: Notes App with Strong Encryption Requirements

**Recommendation:** mattn/go-sqlite3 + go-sqlcipher

**Rationale:**
- SQLCipher is industry standard for database encryption
- 5-15% performance overhead is acceptable for notes app
- Worth CGO complexity for proper encryption
- Battle-tested in production (WhatsApp, Signal, etc.)

**Implementation:**
```go
import _ "github.com/mutecomm/go-sqlcipher"

db, _ := sql.Open("sqlite3", "file:notes.db?_key=your-key&_cipher=aes-256-cbc")
```

**Trade-offs:**
- ❌ Complex cross-compilation
- ✅ Best encryption available
- ✅ Proven security

---

### Use Case 2: Notes App with CGO-Free Requirement

**Option A:** modernc.org/sqlite + Application-Level Encryption (Recommended)

**Rationale:**
- Pure Go, simple deployment
- Encrypt note content field with AES-GCM
- Good enough for most use cases
- ~50% slower than CGO but acceptable for notes

**Implementation:**
```go
import "modernc.org/sqlite"

// Use standard database/sql
db, _ := sql.Open("sqlite", "notes.db")

// Encrypt/decrypt in application layer
encryptedContent := encryptAESGCM(noteContent, key)
```

**Trade-offs:**
- ❌ No full database encryption
- ❌ Metadata visible
- ✅ Simple deployment
- ✅ Pure Go

**Option B:** ncruces/go-sqlite3 with Adiantum VFS (Emerging)

**Rationale:**
- Pure Go with VFS-level encryption
- More complete encryption than app-level
- Newer but promising

**Implementation:**
```go
import "github.com/ncruces/go-sqlite3"
import _ "github.com/ncruces/go-sqlite3/vfs/adiantum"

db, _ := sql.Open("sqlite3", "file:notes.db?vfs=adiantum&key=...")
```

**Trade-offs:**
- ⚠️ Less battle-tested
- ⚠️ Not SQLCipher-compatible
- ✅ Pure Go
- ✅ Full database encryption

---

### Use Case 3: Maximum Performance, No Encryption

**Recommendation:** mattn/go-sqlite3 (without encryption)

**Rationale:**
- Best raw performance
- Most mature ecosystem
- Standard choice for Go + SQLite

**Alternative:** crawshaw.io/sqlite if you need lower-level control

---

### Use Case 4: Prototype/MVP without encryption

**Recommendation:** modernc.org/sqlite

**Rationale:**
- Fastest to deploy (no CGO setup)
- Good enough performance
- Easy to switch to mattn later if needed

---

## Implementation Recommendations for Notes App

### Tier 1: Production-Grade Encryption (Recommended)

**Stack:** mattn/go-sqlite3 + go-sqlcipher

**Setup:**
1. Use Docker for reproducible builds
2. Implement `xgo` for cross-compilation
3. Document CGO setup in README

**Security checklist:**
- ✅ Use 256-bit keys
- ✅ Derive keys from user passphrase with PBKDF2 (100k+ iterations)
- ✅ Never store master key in code
- ✅ Enable page HMAC for tamper detection
- ✅ Enable secure delete

**Code example:**
```go
key := pbkdf2.Key([]byte(userPassphrase), salt, 100000, 32, sha256.New)
hexKey := hex.EncodeToString(key)
dsn := fmt.Sprintf("file:notes.db?_key=%s&_cipher=aes-256-cbc", hexKey)
db, err := sql.Open("sqlite3", dsn)
```

---

### Tier 2: Pure Go with Field-Level Encryption

**Stack:** modernc.org/sqlite + crypto/aes (AES-GCM)

**Setup:**
1. Standard Go build (no CGO)
2. Implement encryption middleware

**Security checklist:**
- ✅ Encrypt note content and title
- ✅ Use AES-GCM (authenticated encryption)
- ✅ Random IV per note
- ✅ Store encrypted blobs as BLOB type
- ⚠️ Metadata not encrypted (timestamps, note count)

**Code example:**
```go
import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
)

func encryptNote(content string, key []byte) ([]byte, error) {
    block, _ := aes.NewCipher(key)
    gcm, _ := cipher.NewGCM(block)
    nonce := make([]byte, gcm.NonceSize())
    rand.Read(nonce)
    return gcm.Seal(nonce, nonce, []byte(content), nil), nil
}
```

---

### Tier 3: Emerging Pure Go with VFS Encryption

**Stack:** ncruces/go-sqlite3 + Adiantum VFS

**Setup:**
1. Monitor project maturity
2. Conduct security review
3. Test compatibility with your use case

**When to consider:**
- ⏰ Wait 6-12 months for more production usage
- ✅ Good for new projects willing to be early adopters
- ⚠️ Not yet recommended for security-critical applications

---

## Key Takeaways

### Critical Question: Can we achieve SQLCipher-level encryption with pure Go?

**Answer: Not currently with the same compatibility and maturity.**

**Options:**
1. **SQLCipher (CGO):** ✅ Yes - industry standard, battle-tested
2. **Pure Go:** ⚠️ Partial solutions available:
   - Application-level encryption (good enough for many cases)
   - ncruces Adiantum/XTS (emerging, not SQLCipher-compatible)

### Decision Framework

```
Do you need SQLCipher compatibility or industry-standard encryption?
├─ YES → Use mattn/go-sqlite3 + go-sqlcipher (accept CGO)
└─ NO → Is any encryption sufficient?
    ├─ YES → Consider ncruces/go-sqlite3 or app-level encryption with modernc
    └─ NO → Use modernc.org/sqlite (pure Go, no encryption)
```

### Final Recommendation for Notes App

**Primary:** mattn/go-sqlite3 + go-sqlcipher
- Accept CGO complexity
- Best encryption available
- Standard solution for encrypted SQLite in Go

**Alternative (if CGO-free is required):** modernc.org/sqlite + AES-GCM application-level encryption
- Pure Go deployment
- Encrypt note content fields
- Good enough for most threat models

**Future consideration:** ncruces/go-sqlite3 with Adiantum
- Monitor project maturity
- Re-evaluate in 6-12 months

---

## Sources

### Performance & Benchmarks
- [SQLite in Go, with and without cgo](https://datastation.multiprocess.io/blog/2022-05-12-sqlite-in-go-with-and-without-cgo.html)
- [Benchmarking SQLite Performance in Go](https://www.golang.dk/articles/benchmarking-sqlite-performance-in-go)
- [go-sqlite-bench GitHub Repository](https://github.com/cvilsmeier/go-sqlite-bench)
- [I benchmarked six Go SQLite drivers - Hacker News](https://news.ycombinator.com/item?id=38626698)

### Library Documentation
- [modernc.org/sqlite - Go Packages](https://pkg.go.dev/modernc.org/sqlite)
- [zombiezen.com/go/sqlite - Go Packages](https://pkg.go.dev/zombiezen.com/go/sqlite)
- [zombiezen.com/go/sqlite reaches 1.0](https://www.zombiezen.com/blog/2023/12/go-sqlite-1-0/)
- [crawshaw.io/sqlite - Go Packages](https://pkg.go.dev/crawshaw.io/sqlite)
- [ncruces/go-sqlite3 GitHub](https://github.com/ncruces/go-sqlite3)

### Encryption & Security
- [SQLCipher Performance Optimization](https://www.zetetic.net/sqlcipher/performance/)
- [SQLCipher GitHub Repository](https://github.com/sqlcipher/sqlcipher)
- [mutecomm/go-sqlcipher GitHub](https://github.com/mutecomm/go-sqlcipher)
- [SQLite Encryption | Knowledge Center](https://www.datasunrise.com/knowledge-center/sqlite-encryption/)
- [Basic Security Practices for SQLite](https://dev.to/stephenc222/basic-security-practices-for-sqlite-safeguarding-your-data-23lh)
- [Encryption and Decryption in Go: A Hands-On Guide](https://dev.to/shrsv/encryption-and-decryption-in-go-a-hands-on-guide-3bcl)

### CGO & Cross-Compilation
- [cgo is not Go - Dave Cheney](https://dave.cheney.net/2016/01/18/cgo-is-not-go)
- [Go: Cross-Compilation Including Cgo](https://ecostack.dev/posts/go-and-cgo-cross-compilation/)
- [xgo - Go CGO cross compiler](https://github.com/karalabe/xgo)

### Production Usage
- [Switch over to modernc.org/sqlite - Gogs Issue](https://github.com/gogs/gogs/issues/7882)
- [Well-Known Users Of SQLite](https://sqlite.org/famous.html)
- [SQLite in Production: 10 examples](https://prototypr.io/note/sqlite-production)

### Additional Resources
- [SQLite Encryption Extension Documentation](https://www.sqlite.org/see/doc/trunk/www/readme.wiki)
- [How SQLCipher Compares to Other Extensions](https://www.zetetic.net/sqlcipher/comparison/)
- [Go and SQLite: when database/sql chafes](https://crawshaw.io/blog/go-and-sqlite)
- [New advanced, CGo-free SQLite package](https://groups.google.com/g/golang-nuts/c/n-MbNQPwwrY)

---

**Document Version:** 1.0
**Last Updated:** 2026-02-02
**Research Scope:** Pure Go vs CGO SQLite encryption for notes applications
