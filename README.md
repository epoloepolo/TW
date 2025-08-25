Response Status: 200
Response Headers: {"X-Fastly-Request-ID":"a61f72a8127a7b5ddd717f1b4189c415168d4f84","Expires":"Mon, 25 Aug 2025 17:08:46 GMT","X-Content-Type-Options":"nosniff","X-XSS-Protection":"1; mode=block","Connection":"keep-alive","Cache-Control":"max-age=300","ETag":"W/\"205af4083f3b7c1feb4a68bbe90f935d4a4437fc3898defb64ec2fc70c125f1a\"","Cross-Origin-Resource-Policy":"cross-origin","Vary":"Authorization,Accept-Encoding","Content-Type":"text/plain; charset=utf-8","Date":"Mon, 25 Aug 2025 17:03:46 GMT","Content-Encoding":"gzip","X-GitHub-Request-Id":"63D7:2AD991:2F7111:3511E8:68AB8435","X-Cache-Hits":"0","Accept-Ranges":"bytes","Strict-Transport-Security":"max-age=31536000","X-Cache":"HIT","Content-Security-Policy":"default-src 'none'; style-src 'unsafe-inline'; sandbox","Via":"1.1 varnish","Access-Control-Allow-Origin":"*","X-Served-By":"cache-sin-wsss1830027-SIN","Source-Age":"121","X-Timer":"S1756141426.122095,VS0,VE1","X-Frame-Options":"deny","Content-Length":"324"}
Response Body: #!name=BoxJs
#!desc=Data manager
#!openUrl=http://boxjs.com
#!author=chavyleung
#!homepage=https://chavyleung.gitbook.io/boxjs/
#!icon=https://raw.githubusercontent.com/chavyleung/scripts/master/box/icons/BoxJs.png

[Rule]                                                        
DOMAIN-SUFFIX,jsdelivr.net,PROXY

[Script]                                                        
http-request ^https?:\/\/(.+\.)?boxjs\.(com|net) script-path=https://raw.githubusercontent.com/chavyleung/scripts/master/box/chavy.boxjs.js, requires-body=true, timeout=120, tag=BoxJs

[MITM]                                                        
hostname = boxjs.com, boxjs.net, *.boxjs.com, *.boxjs.net

------ Script done -------
