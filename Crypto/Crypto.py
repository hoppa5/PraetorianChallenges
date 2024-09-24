#!/usr/bin/env python3

from PIL import Image

import requests
import base64
import os
import re

hashes = {}
CURRENT_DIR = os.path.dirname(os.path.realpath(__file__))

class Colors:
    Red = '\x1b[31m'
    Cyan = '\033[96m'
    End = '\033[0m'

def color_print(text, color):
    return color + text + Colors.End

class ChallengeException(Exception):
    pass

class GuessHandler(object):
    '''
    Handler for the creation of guesses from a crypto challenge
    '''
    CHALLENGE_ANSWER_REGEX = "[A-Z][a-z]+[A-Z][a-z]+[A-Z][a-z]+"
    PNG_OFFSET = 22
    PPM_OFFSET = 14
    data = None

    def decrypt_caeser_cipher(self):
        '''
        Decrypts the ceaser cipher by shifting the provided data to solve
        challenge 1
        '''
        
        result = ""
        shift = 3
        
        for c in self.data:
            if c.isalpha():
                if c.islower():
                    result += chr(((ord(c) - ord('a') + shift) % 26) + ord('a'))
                else:
                    result += chr(((ord(c) - ord('A') + shift) % 26) + ord('A'))
            else:
                # Assuming non-alphabet characters can be preserved
                result += c
        return result

    def convert_base_64_to_png(self, dirName, fileName):
        '''
        Converts the base64 data to a png file to assist with solving challenge 2

        Parameters
        ----------
        dirName : str
            the name of the directory to save the png file in
        fileName : str
            name of the png file the base64 data will be converted to
        '''
        offsetData = self.data[self.PNG_OFFSET:]

        if not os.path.exists(os.path.join(CURRENT_DIR, dirName)):
            os.makedirs(os.path.join(CURRENT_DIR, dirName))

        # Ensure we have a fresh img.png file to work with
        filePath = os.path.join(CURRENT_DIR, dirName, fileName)
        if os.path.isfile(filePath):
            os.remove(filePath)

        with open(filePath, "wb") as pngFile:
            pngFile.write(base64.b64decode(offsetData + ('=' * (4 - (len(offsetData) % 4))))) # add padding as necessary

    def get_answer_from_png(self, filePath):
        '''
        Uses the png file created in the method convert_base_64_to_png to
        get the answer to solve challenge 2

        Parameter
        ---------
        filePath : str
            path to the png file to get the answer from
        '''

        with open (filePath, "rb") as pngFile:
            fileData = pngFile.read()
            decodedFileData = fileData.decode('ascii', 'ignore')
            return re.findall(self.CHALLENGE_ANSWER_REGEX, decodedFileData)[-1]

    def convert_png_to_ppm(self, filePath):
        '''
        Converts a .png file to .ppm

        Parameter
        ---------
        filePath : str
            path to the file to be converted
        ''' 
        if not os.path.exists(filePath):
            raise ChallengeException(color_print("The file path {} does not exist".format(filePath), Colors.Red))
        
        image = Image.open(filePath)
        ppmFilePath = os.path.splitext(filePath)[0] + ".ppm"
        image.save(ppmFilePath, "PPM")
        os.remove(filePath)

    def get_answer_from_ppm(self, filePath):
        '''
        Parses through the ppm file binary converted to ascii text to find the answer

        Parameter
        ---------
        filePath : str
            path to the file to be parsed
        '''
        with open (filePath, "rb") as ppmFile:
            fileData = ppmFile.read()
            decodedFileData = fileData.decode('ascii', 'ignore')
            decodedFileData = decodedFileData[self.PPM_OFFSET:] # the content of the file's binary that should be parsed starts at this offset
            wordCount = 0
            answer = ""
            for c in decodedFileData:
                if c.isalpha():
                    if c.isupper():
                        wordCount += 1
                    if wordCount <= 3:
                        answer += c
                    else:
                        return answer

class ChallengeHandler(GuessHandler):
    '''
    Handler for the crypto challenges
    '''
    CHALLENGE_SECTION = "challenge"
    
    def handle_challenge0(self):
        '''
        Handle challenge 0 to get the challenges started

        This challenge gives you the answer, so nothing special here
        '''
        return self.data
    
    def handle_challenge1(self):
        '''
        Handler to call methods to solve challenge 1
        '''

        return self.decrypt_caeser_cipher()
    
    def handle_challenge2(self):
        '''
        Handler to call methods to solve challenge 2
        '''

        fileName = "img.png"
        dirName = "Challenge2"

        self.convert_base_64_to_png(dirName, fileName)
        return self.get_answer_from_png(os.path.join(CURRENT_DIR, dirName, fileName))
    
    def handle_challenge3(self):
        '''
        Handler to call methods to solve challenge 3
        '''

        pngFileName = "img.png"
        ppmFileName = "img.ppm"
        dirName = "Challenge3"

        self.convert_base_64_to_png(dirName, pngFileName)
        self.convert_png_to_ppm(os.path.join(dirName, pngFileName))
        return self.get_answer_from_ppm(os.path.join(dirName, ppmFileName))

    def handle_challenge4(self):
        '''
        Handler to call methods to solve challenge 3
        '''
        pass
    
    def handle_challenge(self, n, apiHandler):
        '''
        Handles fetching a challenges data and solving it

        Parameters
        ----------
        n : int
            The challenge number
        apiHandler : class instance
            instance of the APIHandler class
        '''
        switch = {
                0: self.handle_challenge0,
                1: self.handle_challenge1,
                2: self.handle_challenge2,
                3: self.handle_challenge3,
                4: self.handle_challenge4,
            }
        
        print(color_print("\n------Handling Challenge {}------".format(n), Colors.Cyan))
        challengeData = apiHandler.fetch(n)
        if n == 4:
            print(challengeData)
        self.data = challengeData[self.CHALLENGE_SECTION]

        try:
            guess = switch[n]()
        except KeyError:
            raise ChallengeException(color_print("\nError: {} is out of bounds for the challenge handler switch's size of {}".format(n, len(switch)), Colors.Red)) from None

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
            print(guess)

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
            raise ChallengeException(color_print(resp.json()['detail'], Colors.Red))
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
            raise ChallengeException(color_print(resp.json()['detail'], Colors.Red))
        return resp.json()
        
def main():
    challengeHandler = ChallengeHandler()
    apiHandler = APIHandler()

    for i in range(0, 5):
        challengeHandler.handle_challenge(i, apiHandler)

    print(color_print("\n------Hashes------", Colors.Cyan))
    for k,v in hashes.items():
        print("Level {}: {}".format(k, v))

if __name__ == "__main__":
    main()
