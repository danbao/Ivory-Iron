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
	Body string
}

func init() {
	http.HandleFunc("/", handler)

	http.HandleFunc("/_IIadmin/", admin)
	http.HandleFunc("/_IIadmin/writeConfig", writeConfig)
}

func handler(w http.ResponseWriter, r *http.Request) {
	var body string
	var ContentType string

	// get the Page
	body, ContentType = checkCache(w, r)

	w.Header().Set("Content-Type", ContentType)
	fmt.Fprintf(w, "%s", body)
}

// Check if item in cache
func checkCache(w http.ResponseWriter, r *http.Request) (string, string) {
	c := appengine.NewContext(r)
	if /*item*/ _, err := memcache.Get(c, "II_file"+r.URL.Path); err == nil {
		// in memcache
		//	return true, item
		return "", ""
	}
	// No token, let's have a look in the datastore
	key := datastore.NewKey(c, "Cache", "II_file"+r.URL.Path, 0, nil)
	var Cache Cache
	if err := datastore.Get(c, key, &Cache); err == nil {
		// In datastorecache
		return string(Cache.Body), ""
	}
	// Not in cache, get the page new
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
		Body: strBody,
	}
	_, err = datastore.Put(c, datastore.NewKey(c, "Cache", "II_file"+r.URL.Path, 0, nil), &Cache)
	if err != nil {
		// Error!
	}
	// Save in memcache
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
