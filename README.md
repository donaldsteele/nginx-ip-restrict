
# nginx-ip-restrict  
nginx-ip-restrict is a rest service written in golang /go that acts as a nginx http basic auth end point that allows you to restrict connections based on country with the option to also block tor end points. 



### Usage 
in this example we are restricting the all requests to wp-admin/*.php to only allow ip address from the United States

    location ~* /wp-admin/.*\.php$ {
	        auth_request     /auth;
	        auth_request_set $auth_status $upstream_status;
	        include snippets/fastcgi-php.conf;
	        fastcgi_pass unix:/var/run/php/php7.0-fpm.sock;                
	        fastcgi_cache_bypass $skip_cache;
	        fastcgi_no_cache $skip_cache;
	        fastcgi_cache WORDPRESS;
	        fastcgi_cache_valid  60m;
    }

    location = /auth {
            internal;
            proxy_pass              http://127.0.0.1:9999/allowbycountry/us/$remote_addr;
            proxy_pass_request_body off;
            proxy_set_header        Content-Length "";
            proxy_set_header        X-Original-URI $request_uri;
        }


the configuration file is simple json file and the structure is 

    {  
	  "listenAddress": "127.0.0.1",  
	  "port": "9999",  
	  "allowedCountries": [  
		    "us",  
			"ca"  
	  ],  
	  "blockTor": true,  
	  "cacheDirectory": "./cache" 
	}



the current endpoint is  /allowbycountry/us/$ip_address
if for example we use the ip 108.211.142.83 which is a known tor exit point 
as verified here [as verified here](https://check.torproject.org/cgi-bin/TorBulkExitList.py?ip=8.8.8.8)  you can look up the country [here](https://www.infobyip.com/ipbulklookup.php)

you will get a return of http status code 403 with the following json 

	    {"code":403,"text":"UnAuthorized"}


by contrast a known us address 5.150.156.21 that is not a tor exit node will return a http status 200 with the following json 

    {"code":200,"text":"Authorized"}
