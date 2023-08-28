# h2Polar
lightweight http/s proxy written in C with ssl intercepting 'n traffic features.

## overview

h2polar is a http/s server proxy with high performance and low memory and CPU usage, useful for tunneling, bypass, network forensics, application security analysis or penetration testing.

## proxy features
* http/s, websocket.
* http/1.0 1.1
* pool thread
* reuse allocated memory
* ip resolve cache
* ssl certificate cache
* easy set up

## traffic features
* [CAPTURE](https://github.com/PowerScript/h2Polar/blob/main/h2polar.cfg#L62) - capture request
* [MODIFY_BODY_REQUEST](https://github.com/PowerScript/h2Polar/blob/main/h2polar.cfg#L55) - modify body request
* [MODIFY_BODY_RESPONSE](https://github.com/PowerScript/h2Polar/blob/main/h2polar.cfg#L59) - modify body response
* [ADD_HEADER_REQUEST](https://github.com/PowerScript/h2Polar/blob/main/h2polar.cfg#L92) - add headers in request
* [ADD_HEADER_RESPONSE](https://github.com/PowerScript/h2Polar/blob/main/h2polar.cfg#L96) - add headers in response
* [REMOVE_HEADER_REQUEST](https://github.com/PowerScript/h2Polar/blob/main/h2polar.cfg#L69) - remove headers in request
* [REMOVE_HEADER_RESPONSE](https://github.com/PowerScript/h2Polar/blob/main/h2polar.cfg#L73) - remove headers in response
* [DOWNLOAD_CONTENT](https://github.com/PowerScript/h2Polar/blob/main/h2polar.cfg#L85) - download content (videos, images, music)
* [SCREENSHOT](https://github.com/PowerScript/h2Polar/blob/main/h2polar.cfg#L65) - take a screenshot when you want
* [FAKE_TLS_EXT_HOSTNAME](https://github.com/PowerScript/h2Polar/blob/main/h2polar.cfg#L77) - bypass firewalls
* [REDIRECT](https://github.com/PowerScript/h2Polar/blob/main/h2polar.cfg#L81) - redirect domains

## https
to https traffic _h2Polar_ use "man in the middle" concept, the server certificates presented to the client are a copy dynamically generated/signed by the proxy, you must set _TLS_MITM_ in _1_ to enable this feacture otherwise traffic will migth manipulate.

so you need install _h2Polar.cer_ on your client to allow ssl traffic or ignore certificate verification (-k curl).

## pac script
h2polar generate pac script according to rules, so you can set your http client with pac script: http://127.0.0.1:51234/h2Polar.pac.

## builds
    _lite: debug_
    gcc h2polar.c -o h2polar.out -pthread -Wall -DDEBUG
    _lite: debug, ssl_
    gcc h2polar.c -o h2polar.exe -pthread -lssl -lcrypto -Wall -DOPENSSL -DDEBUG
    _full: debug, pool, cache_
    gcc h2polar.c -o h2polar.out -pthread -lssl -lcrypto -Wall -DDEBUG -DDNS_MEM_CACHE -DCA_MEM_CACHE -DOPENSSL -DTHREAD_POOL

    _to windows add:
    -lgdi32 -lws2_32 -lGdiplus

## credits
* @RedToor Author
* @z3APA3A [(3Proxy)](https://github.com/3proxy/3proxy/tree/master/src/plugins/SSLPlugin) by SSL Cloning logic.
