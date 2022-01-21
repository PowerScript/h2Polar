# h2Polar
lightweight http/s proxy written in C with ssl intercepting 'n traffic features.

## overview

h2polar is a http/s server proxy with high performance and low memory and CPU usage, useful for tunneling, bypass, network forensics, application security analysis or penetration testing.

only windows is support for now.

## proxy features
* http/s, websocket.
* http/1.0 1.1
* connect, get, post, delete, put and head methods are support 
* pool thread
* reuse alloc memory
* ip resolve cache
* ssl certificate cache
* chunk support
* easy set up

## traffic features
* CAPTURE - log traffic
* MODIFY_BODY_RESPONSE - modified body traffic
* ADD_HEADER_REQUEST - add headers in request
* REMOVE_HEADER_REQUEST - remove headers in request
* REMOVE_HEADER_RESPONSE - remove headers in response
* DOWNLOAD_CONTENT - download content (videos, images, music)
* SCREENSHOT - take a screenshot when you want
* FAKE_TLS_EXT_HOSTNAME - bypass firewalls
* REDIRECT - redirect domains

## https
to https traffic _h2Polar_ use  "man in the middle" concept, the server certificates presented to the client are a copy dynamically generated/signed by the proxy.

so you need install _h2Polar.cer_ on your client to allow ssl traffic or ignore certificate verification (-k curl).

## pac script
h2polar generate pac script according to rules, so you can set your http client with pac script: http://127.0.0.1:51234/h2Polar.pac.

## build
    gcc h2polar.c -o h2polar.exe -pthread -lssl -lcrypto -lgdi32 -lws2_32 -lGdiplus -Wall -static -DDEBUG -DDNS_MEM_CACHE -DCA_MEM_CACHE -DOPENSSL

## credits
* @RedToor Author
* @z3APA3A [(3Proxy)](https://github.com/3proxy/3proxy/tree/master/src/plugins/SSLPlugin) by SSL Cloning logic.
