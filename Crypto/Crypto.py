import base64
import requests
from configparser import ConfigParser

try: input = raw_input
except NameError: pass

# Global values
base = "http://crypto.praetorian.com/{}"
email = "joshharper1997@gmail.com"
auth_token = None
hashes = {}

class GuessHandler(object):
    config = ConfigParser()

    def __init__(self):
        self.config.read('Passwords.ini')

    def decryptCaeserCipher(self, shift, data):
        result = ""
        print("Encrypted text: {}".format(data)) 
        
        for c in data:
            if c.isalpha():
                if c.islower():
                    result += chr(((ord(c) - ord('a') + shift) % 26) + ord('a'))
                else:
                    result += chr(((ord(c) - ord('A') + shift) % 26) + ord('A'))
            else:
                # Assuming non-alphabet characters can be preserved
                result += c
        print("Decrypted text: {}".format(result))
        return result
    
    def convertBase64ToPng(self, data, fileName):
        with open("{}.png".format(fileName), "w") as pngFile:
            pngFile.write(base64.urlsafe_b64decode(data))

def getGuess(n, data):
    guessHandler = GuessHandler()
    try:
        switch = {
                1: guessHandler.decryptCaeserCipher(3, data),
                2: guessHandler.convertBase64ToPng(data, "Challenge2/img"),
                }
        return switch[n]
    except KeyError:
        return None

# Used for authentication
def token(email):
	global auth_token
	if not auth_token:
		url = base.format("api-token-auth/")
		resp = requests.post(url, data={"email":email})
		auth_token = {"Authorization":"JWT " + resp.json()['token']}
		resp.close()
	return auth_token

# Fetch the challenge and hint for level n
def fetch(n):
	url = base.format("challenge/{}/".format(n))
	resp = requests.get(url, headers=token(email))
	resp.close()
	if resp.status_code != 200:
		raise Exception(resp.json()['detail'])
	return resp.json()

# Submit a guess for level n
def solve(n, guess):
	url = base.format("challenge/{}/".format(n))
	data = {"guess": guess}
	resp = requests.post(url, headers=token(email), data=data)
	resp.close()
	if resp.status_code != 200:
		raise Exception(resp.json()['detail'])
	return resp.json()

def addHash(level, h):
    if 'hash' in h: hashes[level] = h['hash']

def handleLevel(n):
    print("\n------Handling level {}------".format(n))
    data = fetch(n)
    print(data)

    guess = getGuess(n, data['challenge'])
    if guess:
        h = solve(n, guess)
        addHash(n, h)

# Fetch level 0
level = 0
data = fetch(level)
print(data)

# Level 0 is a freebie and gives you the password
guess = data['challenge']
h = solve(level, guess)

# If we obtained a hash add it to the dict
addHash(level, h)

handleLevel(1)
handleLevel(2)

print("\n------Displaying Hashes------")
for k,v in hashes.items():
    print("Level {}: {}".format(k, v))

