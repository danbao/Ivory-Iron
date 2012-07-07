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
            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
                    Version 2, December 2004

 Copyright (C) 2004 Sam Hocevar <sam@hocevar.net>

 Everyone is permitted to copy and distribute verbatim or modified
 copies of this license document, and changing it is allowed as long
 as the name is changed.

            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
   TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION

  0. You just DO WHAT THE FUCK YOU WANT TO.

### Authors and Contributors
If you want to help: Just do it! Contact me if you want to get added to this list.
* Lukas Reschke (@LukasReschke)

### Support or Contact
Having trouble with Ivory-Iron? Just contact lukas@statuscode.ch