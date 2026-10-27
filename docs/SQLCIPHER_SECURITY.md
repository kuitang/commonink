# SQLCipher security update

The pinned Go driver is `github.com/benoitpetit/go-sqlcipher/v4` version
`v4.17.0-mira.2`, commit `31cebbd3f5a01515ce8bd24b41bf7d75c64bf652`.
Its SQLCipher 4.17.0 amalgamation embeds SQLite 3.53.3. The module sums are in
go.sum. Recent activity alone does not establish maintenance: the two substantive
fork commits were reviewed against the prior driver and official native source.

## Native source provenance

Official source: https://github.com/sqlcipher/sqlcipher/tree/v4.17.0
(commit `810db22f575ee7cf94ea96a3e91622b5fcece3dc`).
Generate its amalgamation using the official configure/Makefile. Comparing the
result against the pinned module gives only one trailing-whitespace difference
in a generated comment; ignoring trailing whitespace produces an empty diff.
The public sqlite3.h header is identical. The fork's substantive Go change
escapes apostrophes in PRAGMA key before executing it. Build flags replace the
old bundled LibTomCrypt provider with OpenSSL and set the required SQLCipher
initialization/shutdown hooks. FTS5 remains enabled by the existing build tags.

## Encrypted-store compatibility and index migration

SQLCipher 4 defaults remain raw 32-byte keys and 4096-byte pages. No encryption
format migration is performed. The encrypted synthetic corpus was written by
the former SQLCipher 4.4.2/SQLite 3.33.0 driver, including the production notes
schema and historical external-content FTS triggers. Property tests read it,
run the actual idempotent migration, modify empty and nonempty notes, verify
search, checkpoint WAL, copy/restore, reopen and reject a wrong key.

New SQLite checks expose a preexisting FTS synchronization bug: historical
AFTER UPDATE/DELETE triggers retrieve already-modified content. Replace them
with SQLite's documented explicit delete(old values)+insert(new values)
pattern. A transaction replaces the triggers, rebuilds derived search data,
and sets user_version=1. Note bodies and keys remain unchanged. A fault-injection
regression checks that rebuild failure restores the original triggers/version.

FTS reference: https://www.sqlite.org/fts5.html#external_content_tables

## Advisory scope and remaining upstream differences

Official SQLCipher 4.17.0 updates to SQLite 3.53.3, fixing FTS5 heap-write issues
CVE-2026-11822/CVE-2026-11824. These require attacker-controlled SQL/shadow-table
state with defensive mode disabled; ordinary parameterized MATCH text alone
does not establish that condition. SQLite 3.33 also predates the fix for
CVE-2021-20227 (malicious SQL read-after-free); upstream disputes an RCE claim.
concat_ws CVE-2025-3277/CVE-2025-29087 affects a function absent in 3.33, so
assigning it solely by version range would be incorrect.

Official SQLCipher 4.19.0 (SQLite 3.53.4) additionally repairs low-risk
hexkey-URI and sqlcipher_export handling. The application generates raw DEKs
internally and does not expose hexkey URI parameters, SQLCipher export, arbitrary
SQL or database-file import to clients. Those differences remain tracked rather
than hidden. An official 4.19.0 CLI was built independently and also successfully
read/modified the old encrypted fixture; adopting that native baseline through
a maintainable driver is the next dependency refresh.

Primary sources:
- https://www.zetetic.net/blog/ (4.17.0 and 4.19.0 release notes)
- https://www.sqlite.org/cves.html
- https://www.zetetic.net/blog/2025/03/25/sqlcipher-4.7.0-release/

The runtime uses Debian `libssl3t64` 3.5.7-1~deb13u3. Its distribution changelog
explicitly backports the OpenSSL 3.5.8 and 3.5.9 security fixes, including the
September DTLS, QUIC, CRLDP, SM2 and CMP fixes. Judge the full Debian revision
and advisory status rather than comparing only the upstream 3.5.7 string.


2026-10-28 upstream review: SQLCipher 4.20.0 was released on October 27 and
updates its SQLite baseline to 3.54.1. SQLite documents the 3.54.1 heap-buffer
fix as affecting 32-bit builds only; this application is built for amd64. The
other 4.20 changes concern PRAGMA cipher_migrate error deferral and a WebAssembly
finalizer. The application uses neither native cipher_migrate nor WebAssembly;
its MigrateUserDB FTS migration is a separate application operation. The reviewed
Go driver still publishes 4.17.0-mira.2 as its latest tag. No native baseline is
changed merely to match the newest release; the feature-scoped 4.19 differences
above remain tracked, and the next maintained driver refresh should reassess
4.20 or newer against encrypted-store compatibility tests.

- https://www.zetetic.net/blog/2026/10/27/sqlcipher-4.20.0-release/
- https://sqlite.org/changes.html
