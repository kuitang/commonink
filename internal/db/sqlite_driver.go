package db

import (
	"crypto/sha3"
	"database/sql"
	"fmt"
	"strings"

	sqlite3 "github.com/mutecomm/go-sqlcipher/v4"
)

const (
	// SQLiteDriverName is the project-specific SQLCipher driver with custom SQL functions.
	SQLiteDriverName = "sqlite3_agent_notes"
)

func init() {
	sql.Register(SQLiteDriverName, &sqlite3.SQLiteDriver{
		ConnectHook: func(conn *sqlite3.SQLiteConn) error {
			if err := conn.RegisterFunc("sha3", sqliteSHA3, true); err != nil {
				// Some SQLite builds may already expose sha3().
				if strings.Contains(strings.ToLower(err.Error()), "already exists") {
					return nil
				}
				return fmt.Errorf("register sha3 SQL function: %w", err)
			}
			return nil
		},
	})
}

func sqliteSHA3(input any, bits int64) ([]byte, error) {
	data, err := sqliteValueBytes(input)
	if err != nil {
		return nil, err
	}

	switch bits {
	case 224:
		sum := sha3.Sum224(data)
		return sum[:], nil
	case 256:
		sum := sha3.Sum256(data)
		return sum[:], nil
	case 384:
		sum := sha3.Sum384(data)
		return sum[:], nil
	case 512:
		sum := sha3.Sum512(data)
		return sum[:], nil
	default:
		return nil, fmt.Errorf("unsupported sha3 size: %d", bits)
	}
}

func sqliteValueBytes(v any) ([]byte, error) {
	switch x := v.(type) {
	case nil:
		return nil, nil
	case []byte:
		return x, nil
	case string:
		return []byte(x), nil
	default:
		return nil, fmt.Errorf("unsupported sha3 input type: %T", v)
	}
}
