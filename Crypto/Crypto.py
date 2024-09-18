#!/usr/bin/env python3

import requests
import base64
import os
import re

hashes = {}
CHALLENGE_SECTION = "challenge"
CURRENT_DIR = os.path.dirname(os.path.realpath(__file__))

class GuessHandler(object):
    '''
    Handler for the creation of guesses from a crypto challenge
    '''
    CHALLENGE2_ANSWER_REGEX = "[A-Z][a-z]+[A-Z][a-z]+[A-Z][a-z]+"

    def handleChallenge0(self, data):
        '''
        Handle challenge 0 to get the challenges started

        This challenge gives you the answer, so nothing special here
        '''
        return data
    
    def decryptCaeserCipher(self, data):
        '''
        Decrypts the ceaser cipher by shifting the provided data to solve
        challenge 1

        Parameters
        ----------
        data : str
            The encrypted challenge data needing to be decrypted
        '''
        
        result = ""
        shift = 3
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
    
    def convertBase64ToPng(self, dirName, fileName, data):
        '''
        Converts the base64 data to a png file to assist with solving challenge 2

        Parameters
        ----------
        data : bytes
            base64 encoded data needing to be converted to a png file
        '''

        if not os.path.exists(os.path.join(CURRENT_DIR, dirName)):
            os.makedirs(os.path.join(CURRENT_DIR, dirName))

        # Ensure we have a fresh img.png file to work with
        filePath = os.path.join(CURRENT_DIR, dirName, fileName)
        if os.path.isfile(filePath):
            os.remove(filePath)

        with open(filePath, "wb") as pngFile:
            pngFile.write(base64.b64decode(data + ('=' * (4 - (len(data) % 4))))) # add padding as necessary

    def getAnswerFromPng(self, filePath):
        '''
        Uses the png file created in the method convertBase64ToPng to
        get the answer to solve challenge 2

        Parameter
        ---------
        filePath : str
            path to the png file to get the answer from
        '''

        with open (filePath, "rb") as pngFile:
            fileData = pngFile.read()
            decodedFileData = fileData.decode('ascii', 'ignore')
            return re.findall(self.CHALLENGE2_ANSWER_REGEX, decodedFileData)[-1]
            
    def handleChallenge2(self, data):
        offset = 22
        fileName = "img.png"
        dirName = "Challenge2"
        self.convertBase64ToPng(dirName, fileName, data[offset:])
        return self.getAnswerFromPng(os.path.join(CURRENT_DIR, dirName, fileName))
        

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
                0: self.handleChallenge0,
                1: self.decryptCaeserCipher,
                2: self.handleChallenge2,
            }
            return switch[n](data)
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
        while 'hash' not in h:
            i = 1
            # trim the guess down a bit until it is valid.
            # Challenge 2 has an issue where the guess could
            # include an extra couple characters from binary data 
            # after the answer that was converted to ASCII text
            h = apiHandler.solve(n, guess[:-i])
            i += 1

        hashes[n] = h['hash']
        

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
