/* This program is free software. It comes without any warranty, to
 * the extent permitted by applicable law. You can redistribute it
 * and/or modify it under the terms of the Do What The Fuck You Want
 * To Public License, Version 2, as published by Sam Hocevar. See
 * http://sam.zoy.org/wtfpl/COPYING for more details. */

package proxy

import (
	"appengine"
	"appengine/datastore"
	"appengine/memcache"
	"appengine/urlfetch"
	"appengine/user"
	"bytes"
	"csrf"
	"encoding/gob"
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"
	"html/template"
)

/* Server settings */
type Settings struct {
	Host      string
	Cacheable string
}

/* Cache */
type Cache struct {
	Body    []byte
	Headers []byte
}

func init() {
	http.HandleFunc("/", handler)

	http.HandleFunc("/_IIadmin/", admin)
	http.HandleFunc("/_IIadmin/writeConfig", writeConfig)
}

func handler(w http.ResponseWriter, r *http.Request) {
	c := appengine.NewContext(r)

	host, cacheable := getSettings(w, r)

	// Check if we need to redirect to the admin panel (no host)
	if host == "" {
		w.Header().Set("Location", "_IIadmin/")
		w.WriteHeader(http.StatusTemporaryRedirect)
		fmt.Fprintf(w, "")
		return
	}

	// Allowed methods are POST and GET
	if r.Method != "POST" && r.Method != "GET" {
		fmt.Fprintf(w, "%s", "Not allowed")
		return
	}

	// Check if the item is cached
	// Check the memcache
	if item, err := memcache.Get(c, "II_file"+r.URL.Path); err == nil {
		// Decode the map
		var mapCache = map[string][]byte{}
		p := bytes.NewBuffer(item.Value)
		dec := gob.NewDecoder(p)
		dec.Decode(&mapCache)

		// Decode the headers
		var header http.Header
		pHeader := bytes.NewBuffer(mapCache["header"])
		decHeader := gob.NewDecoder(pHeader)
		decHeader.Decode(&header)

		copyHeader(w.Header(), header)
		fmt.Fprintf(w, "%s", mapCache["body"])
		return
	}
	// Check the datastore
	key := datastore.NewKey(c, "Cache", "II_file"+r.URL.Path, 0, nil)
	var readCache Cache
	if err := datastore.Get(c, key, &readCache); err == nil {
		// Decode the header
		var header http.Header
		p := bytes.NewBuffer(readCache.Headers)
		dec := gob.NewDecoder(p)
		dec.Decode(&header)

		// Add to memcache
		saveToMemcache(r, header, string(readCache.Body))

		copyHeader(w.Header(), header) // Copy the HTTP header to the answer
		fmt.Fprintf(w, "%s", readCache.Body)
		return
	}

	// Check if client sends a If-Modified-Since Header
	if r.Header.Get("If-Modified-Since") == "" {

		client := urlfetch.Client(c)

		r.ParseForm() // Parse the form
		req, err := http.NewRequest(r.Method, host+r.URL.Path+"?"+r.URL.RawQuery+"#"+r.URL.Fragment, strings.NewReader(r.Form.Encode()))
		copyCookies(req, r.Cookies()) // Copy the cookies to the request

		resp, _ := client.Do(req)
		defer resp.Body.Close()

		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			c.Infof("Requested URL: %v does not exist", r.URL)
		}

		copyHeader(w.Header(), resp.Header) // Copy the HTTP header to the answer
		body, _ := ioutil.ReadAll(resp.Body)
		replaceStrings := strings.NewReplacer(host, r.URL.Scheme+"://"+r.Host)
		strBody := replaceStrings.Replace(string(body))

		// Run a regex to check if we need to cache the item
		matched, err := regexp.MatchString(cacheable, r.URL.Path)
		if err != nil {
			// Todo: Log error
		}
		if matched {
			saveToDatastore(r, resp.Header, strBody)
			saveToMemcache(r, resp.Header, strBody)
		}
		fmt.Fprintf(w, "%s", strBody)
	} else {
		w.WriteHeader(http.StatusNotModified)
		fmt.Fprintf(w, "")
	}
}

// Save the data to the memcache
func saveToMemcache(r *http.Request, header http.Header, strBody string) {
	c := appengine.NewContext(r)

	mHeader := new(bytes.Buffer) //initialize a *bytes.Buffer
	encHeader := gob.NewEncoder(mHeader)
	encHeader.Encode(header)

	var mapItem = map[string][]byte{}
	mapItem["header"] = mHeader.Bytes()
	mapItem["body"] = []byte(strBody)

	mFile := new(bytes.Buffer) //initialize a *bytes.Buffer
	encFile := gob.NewEncoder(mFile)
	encFile.Encode(mapItem)

	item := &memcache.Item{
		Key:   "II_file" + r.URL.Path,
		Value: mFile.Bytes(),
	}
	memcache.Add(c, item)
}

// Save the data to the datastore
func saveToDatastore(r *http.Request, header http.Header, strBody string) {
	c := appengine.NewContext(r)

	// Gob encode the Headers
	m := new(bytes.Buffer) //initialize a *bytes.Buffer
	enc := gob.NewEncoder(m)
	enc.Encode(header)

	// Save to datastore
	Cache := Cache{
		Body:    []byte(strBody),
		Headers: m.Bytes(),
	}
	datastore.Put(c, datastore.NewKey(c, "Cache", "II_file"+r.URL.Path, 0, nil), &Cache)
}

// Copy the HTTP Headers
func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

// Copy the cookies
func copyCookies(dst *http.Request, src []*http.Cookie) {
	for _, cookie := range src {
		dst.AddCookie(cookie)
	}
}

// Get the settings
func getSettings(w http.ResponseWriter, r *http.Request) (string, string) {
	c := appengine.NewContext(r)
	// Have  a look in the memcache
	var settings = map[string]string{}
	item, err := memcache.Get(c, "Settings")
	if err == nil {
		p := bytes.NewBuffer(item.Value)
		dec := gob.NewDecoder(p)
		dec.Decode(&settings)

		return settings["host"], settings["cacheable"]
	}
	// Have a look in the database
	key := datastore.NewKey(c, "Settings", "Settings", 0, nil)
	var getSettings Settings
	datastore.Get(c, key, &getSettings)

	// And now add it to the memcache
	m := new(bytes.Buffer) //initialize a *bytes.Buffer
	enc := gob.NewEncoder(m)
	settings["host"] = getSettings.Host
	settings["cacheable"] = getSettings.Cacheable
	enc.Encode(settings)
	item = &memcache.Item{
		Key:   "Settings",
		Value: []byte(getSettings.Host),
	}
	memcache.Add(c, item)

	return getSettings.Host, getSettings.Cacheable
}

func writeConfig(w http.ResponseWriter, r *http.Request) {
	// Parse the post data and update the settings
	if csrf.ValidateToken(r, r.FormValue("CSRFToken")) {
		host := r.FormValue("host")
		cacheable := r.FormValue("filetypes")

		c := appengine.NewContext(r)
		// Save in DB
		Settings := Settings{
			Host:      host,
			Cacheable: cacheable,
		}
		_, err := datastore.Put(c, datastore.NewKey(c, "Settings", "Settings", 0, nil), &Settings)
		if err != nil {
			// Todo: Error!
			//return "", ""
		}

		// TODO: Check if data > 1MB
		// Save in memcache
		var settings = map[string]string{}
		settings["host"] = host
		settings["cacheable"] = cacheable

		m := new(bytes.Buffer) //initialize a *bytes.Buffer
		enc := gob.NewEncoder(m)
		enc.Encode(settings)

		item := &memcache.Item{
			Key:   "Settings",
			Value: m.Bytes(),
		}

		// Add the item to the memcache, if the key does not already exist
		if err := memcache.Add(c, item); err == memcache.ErrNotStored {
			memcache.Set(c, item) // Already exists, we need to update
		}

		w.Header().Set("Location", r.Host+"/_IIadmin")
		w.WriteHeader(http.StatusFound)
		return
	}
}

func admin(w http.ResponseWriter, r *http.Request) {
	c := appengine.NewContext(r)
	u := user.Current(c)

	// Check if the user has admin rights
	if u == nil || user.IsAdmin(c) == false {
		url, err := user.LoginURL(c, r.URL.String())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// Redirect to login
		w.Header().Set("Location", url)
		w.WriteHeader(http.StatusFound)
		return
	}

	// Some security related HTTP headers
	w.Header().Set("X-Frame-Options", "DENY")           // Deny frames
	w.Header().Set("X-XSS-Protection", "1; mode=block") // XSS Protection
	w.Header().Set("X-Content-Type-Options", "nosniff") // Disable sniffing

	// Header
	template.Must(template.ParseFiles("templates/header.html")).Execute(w, nil)

	// Adminpanel
	type Data struct {
		CSRFToken string
		Host      string
		Cacheable string
	}
	host, cacheable := getSettings(w, r)
	data := Data{
		CSRFToken: csrf.GetToken(r),
		Host:      host,
		Cacheable: cacheable,
	}
	template.Must(template.ParseFiles("templates/admin.html")).Execute(w, data)

	// Footer
	template.Must(template.ParseFiles("templates/footer.html")).Execute(w, nil)
}
