import urllib.request, base64, json, os, argparse

def client():
    parser = argparse.ArgumentParser(description='Obtain a secret from S5 server.')
    parser.add_argument('--host')
    parser.add_argument('--port')
    parser.add_argument('--token')
    parser.add_argument('--client-file', default='~/.s5client.json')
    parser.add_argument('--no-client-file', action='store_true')
    args = parser.parse_args()

    config = {}
    if not args.no_client_file:
        with open(os.path.expanduser(args.client_file), 'r') as f:
            config = json.load(f)
    if args.host:  config['host']  = args.host
    if args.port:  config['port']  = args.port
    if args.token: config['token'] = args.token

    token = base64.b64decode(config['token'])
    identifier = token[:48]
    symkey = token[48:]

    req =  urllib.request.Request(f"http://{config['host']}:{config['port']}", data=identifier, method='POST')

    try:
        resp = urllib.request.urlopen(req)
        encoded_data = resp.read()
    except:
        print('FAILED')
        exit(1)
    data = base64.b64decode(encoded_data)
    data = bytes([a^b for a, b in zip(data, symkey)])
    length = data[0]
    secret = data[1:(length+1)]
    print(secret.decode(), end='')
