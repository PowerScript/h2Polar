# h2Polar
lightweight http/s proxy written in C with ssl intercepting 'n traffic features.

## overview

h2polar is a http/s server proxy able man-in-the-middle attacks include SSL/TLS encrypted
network connections, useful for network forensics, application security analysis or penetration testing.

only windows is support for now.

## https
install _h2Polar.cer_ on your system to allow ssl traffic.

## pac
set your client proxy pac with http://127.0.0.1:51234/h2Polar.pac.

## traffic features
* CAPTURE - log traffic
* REMOVE_HEADER_REQUEST - remove headers
* REMOVE_HEADER_RESPONSE - remove headers
* DOWNLOAD_CONTENT - download content
* SCREENSHOT - take screenshot
* FAKE_TLS_EXT_HOSTNAME - change sni hostname
* INJECT - inject traffic
* REDIRECT - redirect domains

## build
    gcc h2polar.c -o h2polar.exe -pthread -lssl -lcrypto -lgdi32 -lws2_32 -lGdiplus -Wall -DDEBUG -DDNS_MEM_CACHE -DCA_MEM_CACHE -DOPENSSL
