# oauth2-proxy.py

## Description

oauth2-proxy.py is OAuth2.0 client app for auth_request of nginx.

ref. http://nginx.org/en/docs/http/ngx_http_auth_request_module.html
```
    location / {
        auth_request /oauth2/auth;
        error_page 401 = /oauth2/start;

        root   /usr/share/nginx/html;
        index  index.html index.htm;
    }

    location /oauth2 {
        proxy_pass http://oauth2-proxy:5000;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header X-Original-URI $request_uri;
    }
```

## Install

```
$ pip install -r requirements.txt
```

## Configs

Please specify following keys as environment variable.

ref. https://github.com/goru/oauth2-proxy.py/blob/main/main.py#L16-L23
```
configs = {
    'provider': os.environ['PROVIDER'],
    'client_id': os.environ['CLIENT_ID'],
    'redirect_uri': os.environ['REDIRECT_URI'],
    'scope': os.environ['SCOPE'],
    'accept_users': os.environ['ACCEPT_USERS'].split(','),
    'max_sessions': int(os.environ['MAX_SESSIONS'])
}
```

## Run

```
$ python main.py
```
