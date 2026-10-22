Synthetic compatibility corpus v4.4.2.db
Writer: github.com/mutecomm/go-sqlcipher/v4 v4.4.2 / SQLCipher4.4.2 / SQLite3.33.0.
Key:32 bytes with byte value65 (public test key); page size4096.
Includes former production notes schema, historical external-content FTS5 triggers, preseeded empty-token and searchable notes, plus a standalone porter-FTS fixture. No user data.
SHA256:0937a314d02da0db384dfbb6529d1df8fc7d2752b9ab0c1ce5723f9e16bb2878
Generation source and schema retained with remediation evidence in go-services/sqlcipher-legacy-fixture-generator.go and sqlcipher-legacy-schema.sql. They use the old driver intentionally only to construct this regression corpus; the production module no longer imports it.
