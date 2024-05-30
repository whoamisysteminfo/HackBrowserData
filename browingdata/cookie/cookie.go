package cookie

import (
	"database/sql"
	"log/slog"
	"os"
	"strings"
	
	_ "modernc.org/sqlite"

	"github.com/moond4rk/hackbrowserdata/crypto"
	"github.com/moond4rk/hackbrowserdata/extractor"
	"github.com/moond4rk/hackbrowserdata/types"
	"github.com/moond4rk/hackbrowserdata/utils/typeutil"
)

func init() {
	extractor.RegisterExtractor(types.ChromiumCookie, func() extractor.Extractor {
		return new(ChromiumCookie)
	})
	extractor.RegisterExtractor(types.FirefoxCookie, func() extractor.Extractor {
		return new(FirefoxCookie)
	})
}

type ChromiumCookie []cookie

type cookie struct {
	Host         string      	`json:"domain"`
	Path         string			`json:"path"`
	KeyName      string			`json:"name"`
	encryptValue []byte
	Value        string			`json:"value"`
	IsSecure     bool			`json:"secure"`
	IsHTTPOnly   bool			`json:"httpOnly"`
	Session      bool			`json:"session"`
	IsHostKey	 bool			`json:"hostOnly"`
	ExpireDate   float64	    `json:"expirationDate"`
	SameSite	 string			`json:"sameSite"`
	StoreId      string         `json:"storeId"`
}

const (
	queryChromiumCookie = `SELECT name, encrypted_value, host_key, path, creation_utc, expires_utc, is_secure, is_httponly, has_expires, is_persistent, samesite FROM cookies`
)

func (c *ChromiumCookie) Extract(masterKey []byte) error {
	db, err := sql.Open("sqlite", types.ChromiumCookie.TempFilename())
	if err != nil {
		return err
	}
	defer os.Remove(types.ChromiumCookie.TempFilename())
	defer db.Close()
	rows, err := db.Query(queryChromiumCookie)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var (
			key, host, path, siteFlag                     string
			isSecure, isHTTPOnly, hasExpire, isPersistent int
			sameSite, hostOnly   						  int
			createDate, expireDate                        int64
			value, encryptValue                           []byte
		)
		
		if err = rows.Scan(&key, &encryptValue, &host, &path, &createDate, &expireDate, &isSecure, &isHTTPOnly, &hasExpire, &isPersistent, &sameSite); err != nil {
			slog.Error("scan chromium cookie error", "err", err)
		}
		
		switch sameSite {
		case -1:
			siteFlag = "unspecified"
		case 0:
			siteFlag = "no_restriction"
		case 1:
			siteFlag = "lax"
		case 2:
			siteFlag = "strict"
		default:
			siteFlag = "unspecified"
		}
		
		if strings.HasPrefix(host, ".") {
			hostOnly = 0
		} else {
			hostOnly = 1
		}

		cookie := cookie{
			KeyName:      key,
			Host:         host,
			Path:         path,
			encryptValue: encryptValue,
			IsSecure:     typeutil.IntToBool(isSecure),
			IsHTTPOnly:   typeutil.IntToBool(isHTTPOnly),
			Session:      !typeutil.IntToBool(isPersistent),
			ExpireDate:   (float64(expireDate) - 11644473600000000) / 1000 / 1000,
			SameSite:	  siteFlag,
			IsHostKey:    typeutil.IntToBool(hostOnly),
			StoreId:	  "0",
		}
		
		if len(encryptValue) > 0 {
			if len(masterKey) == 0 {
				value, err = crypto.DecryptWithDPAPI(encryptValue)
			} else {
				value, err = crypto.DecryptWithChromium(masterKey, encryptValue)
			}
			if err != nil {
				slog.Error("decrypt chromium cookie error", "err", err)
			}
		}
		
		cookie.Value = string(value)

		*c = append(*c, cookie)
	}

	return nil
}

func (c *ChromiumCookie) Name() string {
	return "cookie"
}

func (c *ChromiumCookie) Len() int {
	return len(*c)
}

type FirefoxCookie []cookie

const (
	queryFirefoxCookie = `SELECT name, value, host, path, creationTime, expiry, isSecure, isHttpOnly FROM moz_cookies`
)

func (f *FirefoxCookie) Extract(_ []byte) error {
	db, err := sql.Open("sqlite", types.FirefoxCookie.TempFilename())
	if err != nil {
		return err
	}
	defer os.Remove(types.FirefoxCookie.TempFilename())
	defer db.Close()

	rows, err := db.Query(queryFirefoxCookie)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var (
			name, value, host, path string
			isSecure, isHTTPOnly    int
			creationTime, expiry    int64
		)
		if err = rows.Scan(&name, &value, &host, &path, &creationTime, &expiry, &isSecure, &isHTTPOnly); err != nil {
			slog.Error("scan firefox cookie error", "err", err)
		}
		*f = append(*f, cookie{
			KeyName:    name,
			Host:       host,
			Path:       path,
			IsSecure:   typeutil.IntToBool(isSecure),
			IsHTTPOnly: typeutil.IntToBool(isHTTPOnly),
			ExpireDate: (float64(expiry) - 11644473600000000) / 1000 / 1000,
			Value:      value,
		})
	}

	return nil
}

func (f *FirefoxCookie) Name() string {
	return "cookie"
}

func (f *FirefoxCookie) Len() int {
	return len(*f)
}
