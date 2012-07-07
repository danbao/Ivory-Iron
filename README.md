# Ivory-Iron
Ivory-Iron is a lightweigth, easy to setup reverse proxy for Google App Engine written in Golang.

### Features
* Caching of pages (Memcache + Datastore)

### Setup
* Register a Google App Engine account (https://appengine.google.com/)
* Change the Application name in app.yaml
* Upload to Google App Engine

```
$ cd Ivory-Iron
$ python appcfg.py update ./
```

* Visit the admin panel (http://APPID.appspot.com/_IIadmin/) and setup Ivory-Iron.

### License
This program is free software. It comes without any warranty, to the extent permitted by applicable law. You can redistribute itnand/or modify it under the terms of the Do What The Fuck You Want To Public License, Version 2, as published by Sam Hocevar. See http://sam.zoy.org/wtfpl/COPYING for more detail

### Authors and Contributors
If you want to help: Just do it! Contact me if you want to get added to this list.
* Lukas Reschke (@LukasReschke)

### Support or Contact
Having trouble with Ivory-Iron? Just contact lukas@statuscode.ch