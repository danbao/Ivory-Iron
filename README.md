# Ivory-Iron
Ivory-Iron is a lightweigth, easy to setup reverse proxy for Google App Engine written in Golang.

### Features
* Caching of pages (Memcache + Datastore)
                             
#### Not yet implemented
* Support for Cookies

### Setup
* Register a Google App Engine account (https://appengine.google.com/)
* Change the Application name in app.yaml
* Upload to Google App Engine

```
$ cd Ivory-Iron
$ python appcfg.py update ./
```

* Visit the admin panel (http://APPID.appspot.com/_IIadmin/) and setup Ivory-Iron. (Just copy and paste the examples ;-))

### Authors and Contributors
* Lukas Reschke (@LukasReschke)

### Support or Contact
Having trouble with Ivory-Iron? Just contact lukas@statuscode.ch