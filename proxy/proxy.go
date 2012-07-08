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
	"csrf"
	"fmt"
	"io/ioutil"
	"mustache"
	"net/http"
	"strings"
)

/* Server settings */
type Settings struct {
	Host string
}

/* Cache */
type Cache struct {
	Body        []byte
	ContentType string
}

func init() {
	http.HandleFunc("/", handler)

	http.HandleFunc("/_IIadmin/", admin)
	http.HandleFunc("/_IIadmin/writeConfig", writeConfig)
}

func handler(w http.ResponseWriter, r *http.Request) {
	/* var body string
	var ContentType string*/

	/*  TODO: This is the caching part etc, before we implement it, we should have already a "good" base
	// get the Page
	body, ContentType = getData(w, r)

	// TODO: cache control
	c := appengine.NewContext(r)
	client := urlfetch.Client(c)
	resp, err := client.Get("http://owncloud.org/" + r.URL.Path)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		//return 
	}
	defer resp.Body.Close()
	CacheControl := resp.Header.Get("Cache-Control")

	w.Header().Set("Content-Type", ContentType)
	w.Header().Set("Cache-Control", CacheControl)
	fmt.Fprintf(w, "%s", body) */

	// Allowed methods are POST and GET
	if r.Method != "POST" && r.Method != "GET" {
		fmt.Fprintf(w, "%s", "Not allowed")
		return
	}

	c := appengine.NewContext(r)
	client := urlfetch.Client(c)

	r.ParseForm() // Parse the form
	req, err := http.NewRequest(r.Method, "http://www.google.com/"+r.URL.Path+"?"+r.URL.RawQuery+"#"+r.URL.Fragment, strings.NewReader(r.Form.Encode()))

	resp, _ := client.Do(req)
	defer resp.Body.Close()
	if r.Header.Get("If-Modified-Since") == "" {

		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			c.Infof("Requested URL: %v does not exist", r.URL)
		}

		copyHeader(w.Header(), resp.Header) // Copy the HTTP header to the answer
		body, _ := ioutil.ReadAll(resp.Body)
		replaceStrings := strings.NewReplacer("http://www.google.com/", r.Host)
		strBody := replaceStrings.Replace(string(body))

		fmt.Fprintf(w, "%s", strBody)
	} else {
		w.WriteHeader(http.StatusNotModified)
		fmt.Fprintf(w, "")
	}
}

// Copy the HTTP Headers
func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

// Get the data
func getData(w http.ResponseWriter, r *http.Request) (string, string) {
	c := appengine.NewContext(r)

	// Lets first have a look in the memcache, maybe it's cached
	if item, err := memcache.Get(c, "II_file"+r.URL.Path); err == nil {
		item_Contenttype, _ := memcache.Get(c, "II_file"+r.URL.Path+"ContentType") // todo error checking
		return string(item.Value), string(item_Contenttype.Value)
	}
	// No? - Maybe it's in the datastore?
	key := datastore.NewKey(c, "Cache", "II_file"+r.URL.Path, 0, nil)
	var Cache Cache
	if err := datastore.Get(c, key, &Cache); err == nil {
		// TODO: add to memcache
		// In the memcache, now put it also to the cache
		return string(Cache.Body), Cache.ContentType
	}

	// Not cached, we need to get the page from the server.
	return getPage(w, r)
}

// Get the page
func getPage(w http.ResponseWriter, r *http.Request) (string, string) {
	c := appengine.NewContext(r)
	client := urlfetch.Client(c)
	resp, err := client.Get("http://owncloud.org/" + r.URL.Path)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		//return 
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)

	// Do the replacement
	replaceStrings := strings.NewReplacer("owncloud.org", r.Host)
	strBody := replaceStrings.Replace(string(body))

	// Save in DB
	Cache := Cache{
		Body:        []byte(strBody),
		ContentType: resp.Header.Get("Content-Type"),
	}
	_, err = datastore.Put(c, datastore.NewKey(c, "Cache", "II_file"+r.URL.Path, 0, nil), &Cache)
	if err != nil {
		// Todo: Error!
		//return "", ""
	}
	// Save in memcache
	// TODO: Check if data > 1MB
	// Create an Item
	item := &memcache.Item{
		Key:   "II_file" + r.URL.Path,
		Value: []byte(strBody),
	}
	item_Contenttype := &memcache.Item{
		Key:   "II_file" + r.URL.Path + "ContentType",
		Value: []byte(resp.Header.Get("Content-Type")),
	}
	// Add the item to the memcache, if the key does not already exist
	if err := memcache.Add(c, item); err == memcache.ErrNotStored {
		//c.Log("item with key %q already exists", item.Key)

	} else if err != nil {
		//c.Log("error adding item: %v", err)
	}
	// Add the item to the memcache, if the key does not already exist
	if err := memcache.Add(c, item_Contenttype); err == memcache.ErrNotStored {
		//c.Log("item with key %q already exists", item.Key)

	} else if err != nil {
		//c.Log("error adding item: %v", err)
	}
	return strBody, string(resp.Header.Get("Content-Type"))
}

func writeConfig(w http.ResponseWriter, r *http.Request) {
	// Parse the post data and update the settings
	if csrf.ValidateCSRFToken(r, r.FormValue("CSRFToken")) {
		host := r.FormValue("host")
		fmt.Fprintf(w, host)
	}
	w.Header().Set("Location", r.Host+"/_IIadmin")
	w.WriteHeader(http.StatusFound)
	return
}
func admin(w http.ResponseWriter, r *http.Request) {
	c := appengine.NewContext(r)
	u := user.Current(c)
	var x = map[interface{}]interface{}{} // Mustache in it...

	// Check if the user is logged in and has admin rights
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
	// CSRF
	if csrf.CheckForCSRFToken(r) == false {
		// Generate one 
		csrf.GenerateCSRFToken(r)
	} else {
		// Read it out
		x["csrfToken"] = csrf.GetToken(r)
	}

	// Enhance security
	w.Header().Set("X-Frame-Options", "DENY")           // Deny frames
	w.Header().Set("X-XSS-Protection", "1; mode=block") // XSS Protection
	w.Header().Set("X-Content-Type-Options", "nosniff") // Disable sniffing

	data := mustache.RenderFile("templates/admin.mustache", x)
	fmt.Fprintf(w, data)
}
