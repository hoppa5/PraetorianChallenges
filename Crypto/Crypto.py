#!/usr/bin/env python3

import base64
import requests
import os

from configparser import ConfigParser

hashes = {}
CHALLENGE_SECTION = "challenge"
CURRENT_DIR = os.path.dirname(os.path.realpath(__file__))

class GuessHandler(object):
    '''
    Handler for the creation of guesses from a crypto challenge
    '''

    config = ConfigParser()

    def __init__(self):
        self.config.read('Passwords.ini')

    def handleChallenge0(self, data):
        '''
        Handle challenge 0 to get the challenges started

        This challenge gives you the answer, so nothing special here
        '''
        return data[CHALLENGE_SECTION]
    
    def decryptCaeserCipher(self, shift, data):
        '''
        Decrypts the ceaser cipher by shifting the provided data to solve
        challenge 1

        Parameters
        ----------
        shift : int
            The shift key for decrypting the ciphered data
        data : str
            The encrypted challenge data needing to be decrypted
        '''

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
    
    def convertBase64ToPng(self, data, dirName, fileName):
        '''
        Converts the base64 data to a png file to assist with solving challenge 2

        Parameters
        ----------
        data : str
            base64 encoded data needing to be converted to a png file
        dirName : str
            The name of the directory that will hold the png file
        fileName : str
            The name of the png file that the data will be converted to
        '''
        if not os.path.exists(os.path.join(CURRENT_DIR, dirName)):
            os.makedirs(os.path.join(CURRENT_DIR, dirName))

        with open(os.path.join(CURRENT_DIR, dirName, fileName), "w") as pngFile:
            pngFile.write(base64.urlsafe_b64decode(data))

    def getGuess(self, n, data):
        '''
        Makeshift switch statement to call the appropriate class method to solve 
        a challenge

        Parameters
        ----------
        n : int
            The challenge number
        data : str
            The encoded text that needs to be decoded
        '''

        try:
            switch = {
                    1: self.decryptCaeserCipher(3, data),
                    2: self.convertBase64ToPng(data, "Challenge2", "img.png"),
                    }
            return switch[n]
        except KeyError:
            return None
        
class APIHandler(object):
    '''
    Handler for Praetorian's crypto challenge API.

    Gets the authentication token, fetches challenge data, and submits 
    guesses to solve challenges
    '''

    base = "http://crypto.praetorian.com/{}"
    email = "joshharper1997@gmail.com"
    auth_token = None

    def token(self):
        '''
        Gets the token used for authentication to the API 
        '''
        if not self.auth_token:
            url = self.base.format("api-token-auth/")
            resp = requests.post(url, data={"email":self.email})
            self.auth_token = {"Authorization":"JWT " + resp.json()['token']}
            resp.close()

        return self.auth_token

    def fetch(self, n):
        '''
        Fetches the challenge and hint for a challenge

        Parameter
        ---------
        n : int
            the challenge number
        '''

        url = self.base.format("challenge/{}/".format(n))
        resp = requests.get(url, headers=self.token())
        resp.close()
        if resp.status_code != 200:
            raise Exception(resp.json()['detail'])
        return resp.json()

    def solve(self, n, guess):
        '''
        Submits guesses to solve a challenge

        Parameters
        ----------
        n : int
            the challenge number
        guess : str
            the guess to solve a crypto challenge
        '''

        url = self.base.format("challenge/{}/".format(n))
        data = {"guess": guess}
        resp = requests.post(url, headers=self.token(), data=data)
        resp.close()
        if resp.status_code != 200:
            raise Exception(resp.json()['detail'])
        return resp.json()

def addHash(n, h):
    '''
    Adds a hash to the global hashes dictionary

    Parameters
    ----------
    n : int
        The challenge number
    h : str
        The hash that gets returned when a challenge is solved
    '''
    if 'hash' in h: hashes[n] = h['hash']

def handleLevel(n, guessHandler, apiHandler):
    '''
    Handles fetching a challenges data and solving it

    Parameters
    ----------
    n : int
        The challenge number
    guessHandler : class instance
        instance of the GuessHandler class
    apiHandler : class instance
        instance of the APIHandler class
    '''

    print("\n------Handling level {}------".format(n))
    data = apiHandler.fetch(n)
    print(data)

    guess = guessHandler.getGuess(n, data[CHALLENGE_SECTION])
    if guess:
        h = apiHandler.solve(n, guess)
        addHash(n, h)

def main():
    guessHandler = GuessHandler()
    apiHandler = APIHandler()

    for i in range(0, 3):
        handleLevel(i, guessHandler, apiHandler)

    print("\n------Displaying Hashes------")
    for k,v in hashes.items():
        print("Level {}: {}".format(k, v))

if __name__ == "__main__":
    main()
