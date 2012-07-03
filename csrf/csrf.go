package csrf

import (
	"appengine"
	"appengine/datastore"
	"appengine/memcache"
	"appengine/user"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/gob"
	"io"
	"net/http"
	"strings"
)

/* For the CSRF Token */
type SecurityToken struct {
	Token string
}

/*
 * Checks if there is an entry in the memcache
 */
func CheckMemcache(r *http.Request, entry string) bool {
	// Get the item from the memcache
	c := appengine.NewContext(r)
	if _, err := memcache.Get(c, entry); err == memcache.ErrCacheMiss {
		// Item not in cache
		return false
	} else if err != nil {
		// error
		return false
	} else {
		// in cache
		return true
	}
	// Should never happen
	return false
}

/*
 * Function to return a random string
 */
func MakeRandomString(size int) string {
	var buf []byte = make([]byte, size)

	_, err := io.ReadFull(rand.Reader, buf)
	if err != nil {
		return ""
	}

	var encbuf []byte = make([]byte, base64.StdEncoding.EncodedLen(len(buf)))
	base64.StdEncoding.Encode(encbuf, buf)

	return strings.Replace(string(encbuf), "+", "_", -1)
}

/*
 * Get a token
 */
func GetToken(r *http.Request) string {
	c := appengine.NewContext(r)
	u := user.Current(c)
	var securityToken string

	// CSRF Token name
	csrfTokenUserID := "CSRF" + u.ID
	// Check if we have a token in the memcache 
	if CheckMemcache(r, csrfTokenUserID) {
		// Yes there is a token, make it readable
		// Get the item from the memcache
		item, _ := memcache.Get(c, csrfTokenUserID)

		//create a bytes.Buffer type with n, type []byte  
		p := bytes.NewBuffer(item.Value)

		// Decode the entity
		dec := gob.NewDecoder(p)
		err := dec.Decode(&securityToken)
		if err != nil {
			panic(err)
		}
		return securityToken
	} else {
		// No token, let's have a look in the datastore
		key := datastore.NewKey(c, "SecurityToken", csrfTokenUserID, 0, nil)
		var datastoreSecurityToken SecurityToken
		if err := datastore.Get(c, key, &datastoreSecurityToken); err != nil {
			// Error, return ""
			return ""
		}
		return datastoreSecurityToken.Token
	}
	return ""
}

/*
 * Check for token
 */
func CheckForCSRFToken(r *http.Request) bool {
	c := appengine.NewContext(r)
	u := user.Current(c)
	csrfTokenUserID := "CSRF" + u.ID

	// Check if it is in the memcache
	if CheckMemcache(r, csrfTokenUserID) {
		return true
	}
	// Check if it is in the Datastore
	key := datastore.NewKey(c, "SecurityToken", csrfTokenUserID, 0, nil)
	var datastoreSecurityToken SecurityToken
	if err := datastore.Get(c, key, &datastoreSecurityToken); err == nil {
		//All fine
		return true
	}

	return false
}

/*
 * CSRF Generator
 */
func GenerateCSRFToken(r *http.Request) {
	c := appengine.NewContext(r)
	u := user.Current(c)
	csrfToken := MakeRandomString(20)

	/* 
	 * Insert the CSRF into the Memcache
	 */
	// Encode the entity
	//initialize a *bytes.Buffer
	m := new(bytes.Buffer)
	enc := gob.NewEncoder(m)
	enc.Encode(csrfToken)
	csrfTokenUserID := "CSRF" + u.ID
	item := &memcache.Item{
		Key:   csrfTokenUserID,
		Value: m.Bytes(),
	}
	memcache.Add(c, item)

	/* 
	 * Insert the CSRF into the DB
	 */
	SecurityToken := SecurityToken{
		Token: csrfToken,
	}
	// we use the Userid as keyname - nice for a direct lookup
	_, err := datastore.Put(c, datastore.NewKey(c, "SecurityToken", u.ID, 0, nil), &SecurityToken)
	if err != nil {
		// Error!
	}

}

/*
 * Validate CSRF Token
 */
func ValidateCSRFToken(r *http.Request, token string) bool {
	c := appengine.NewContext(r)
	u := user.Current(c)
	var securityToken string

	// CSRF Token name
	csrfTokenUserID := "CSRF" + u.ID
	// Check if we have a token in the memcache 
	if CheckMemcache(r, csrfTokenUserID) {
		// Yes there is a token, make it readable
		// Get the item from the memcache
		item, _ := memcache.Get(c, csrfTokenUserID)

		//create a bytes.Buffer type with n, type []byte  
		p := bytes.NewBuffer(item.Value)

		// Decode the entity
		dec := gob.NewDecoder(p)
		err := dec.Decode(&securityToken)
		if err != nil {
			panic(err)
		}

		// Let's make a lookup
		if token == securityToken {
			// They match!
			return true
		}
	} else {
		// No token, let's have a look in the datastore
		key := datastore.NewKey(c, "SecurityToken", csrfTokenUserID, 0, nil)
		var datastoreSecurityToken SecurityToken
		if err := datastore.Get(c, key, &datastoreSecurityToken); err != nil {
			// Error, return false
			return false
		}
		// Let's make a lookup
		if token == datastoreSecurityToken.Token {
			// They match!
			return true
		}
	}
	return false
}
