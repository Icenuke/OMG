#!/usr/bin/env python
# -*- coding:utf-8 -*-

"""
    This code is a generator of Login, Mail and Password
    thanks to a words list insert in extern file
    with this word list the code generate a Login, Mail and Password
    thank to mix of word.

"""

from sys import argv
from os import listdir, getcwd
from base64 import b64encode
from hashlib import md5, sha1, sha256
from urllib.parse import quote
from datetime import datetime
from binascii import hexlify


# open file which have the word list
def ReadFile():
    """
        Read the file with the word list and add the word
        in list which return in other function
        :return: word list
    """

    if "OhMyWordList.txt" in listdir(getcwd()):
        with open(getcwd()+'\\OhMyWordList.txt') as rdf:
            wordList = [ word[:-1] for word in rdf.readlines() ]
        #wordList = [ word[:-1] for word in open(getcwd()+'\\OhMyWordList.txt').readlines() ]
        return wordList
    else:
        print("/!\ Can\'t find the OhMyWordList.ice in this directory. /!\\\n      Stop IVGenerator.")


# create file and write the result in this
def WriteFile(Name, Result):
    """
        Write file with the result of different function
        Password, Login, Mail
        :param Name: Name of file create or open
        :param Result: The Different Password, Login, Mail create
        :return: Nothing
    """

    # create or open file PasswordResult.ice and write the password generate
    with open(Name, 'a+') as wf:
        wf.writelines(str(resultLine+ "\n") for resultLine in Result)
    #open(Name, 'a+').writelines(str(resultLine+ "\n") for resultLine in Result)


# Hash the result with MD5, SHA-1, SHA-2 and encode this in Hexa, Base64, and URL Encode
def HashResult(Result):                                          
    #                                              HEXA Conversion                                 Encode Base64       URL Encode          HASH MD5                HASH SHA1                   HASH SHA256
    return "%s \t %s \t %s \t %s \t %s \t %s" % (hexlify(Result.encode()).decode(), b64encode(Result.encode()).decode(), quote(Result.encode()), md5(Result.encode()).hexdigest(), sha1(Result.encode()).hexdigest(), sha256(Result.encode()).hexdigest())
    

# Gen Passwoed with the word list
def GenLogin():
    """
        The mix is with word list only
        :return: generated Login
    """
    # add in list the list recovered by the function OpenFile
    wordList = ReadFile()

    # Define new list for the result
    finalLoginList = []
    finalLoginList.append("Login \t\t Hexa Encode \t\t\t Base64 \t\t URL Encode \t\t\t Hash MD5 \t\t\t\t\t\t Hash SHA-1 \t\t\t\t\t\t\t\t Hash SHA-256")
    print()

    # try:
    for fstWord in wordList:
        finalLoginList.append("%s \t\t %s" % (fstWord, HashResult("%s" % (fstWord))))
        finalLoginList.append("%s%s \t\t %s" % (fstWord[0].upper(), fstWord[1:], HashResult("%s%s" % (fstWord[0].upper(), fstWord[1:]))))
        print(fstWord)

        for scdWord in wordList:
            finalLoginList.append("%s%s \t %s" % (fstWord, scdWord, HashResult("%s%s" % (fstWord, scdWord))))
            finalLoginList.append("%s%s \t %s" % (fstWord[:3], scdWord, HashResult("%s%s" % (fstWord[:3], scdWord))))
            finalLoginList.append("%s%s \t %s" % (fstWord[0], scdWord, HashResult("%s%s" % (fstWord[0], scdWord))))
            finalLoginList.append("%s%s \t %s" % (fstWord, scdWord[0], HashResult("%s%s" % (fstWord, scdWord[0]))))
            finalLoginList.append("%s%s \t %s" % (fstWord[:3], scdWord, HashResult("%s%s" % (fstWord[:3], scdWord))))

            finalLoginList.append("%s%s%s \t %s" % (fstWord, scdWord[0].upper(), scdWord[1:], HashResult("%s%s%s" % (fstWord, scdWord[0].upper(), scdWord[1:]))))
            finalLoginList.append("%s%s%s \t %s" % (fstWord[:3], scdWord[0].upper(), scdWord[1:], HashResult("%s%s%s" % (fstWord[:3], scdWord[0].upper(), scdWord[1:]))))
            finalLoginList.append("%s%s%s \t %s" % (fstWord[0], scdWord[0].upper(), scdWord[1:], HashResult("%s%s%s" % (fstWord[0], scdWord[0].upper(), scdWord[1:]))))
            finalLoginList.append("%s%s \t %s" % (fstWord, scdWord[0].upper(), HashResult("%s%s" % (fstWord, scdWord[0].upper()))))

            finalLoginList.append("%s%s%s \t %s" % (fstWord[0].upper(), fstWord[1:], scdWord, HashResult("%s%s%s" % (fstWord[0].upper(), fstWord[1:], scdWord))))
            finalLoginList.append("%s%s%s \t %s" % (fstWord[0].upper(), fstWord[1:3], scdWord, HashResult("%s%s%s" % (fstWord[0].upper(), fstWord[1:3], scdWord))))
            finalLoginList.append("%s%s \t %s" % (fstWord[0].upper(), scdWord, HashResult("%s%s" % (fstWord[0].upper(), scdWord))))
            finalLoginList.append("%s%s%s \t %s" % (fstWord[0].upper(), fstWord[1:], scdWord[0], HashResult("%s%s%s" % (fstWord[0].upper(), fstWord[1:], scdWord[0]))))

            finalLoginList.append("%s%s%s%s \t %s" % (fstWord[0].upper(), fstWord[1:], scdWord[0].upper(), scdWord[1:], HashResult("%s%s%s%s" % (fstWord[0].upper(), fstWord[1:], scdWord[0].upper(), scdWord[1:]))))
            finalLoginList.append("%s%s%s \t %s" % (fstWord[0].upper(), fstWord[1:3], scdWord[1:], HashResult("%s%s%s" % (fstWord[0].upper(), fstWord[1:3], scdWord[1:]))))
            finalLoginList.append("%s%s%s \t %s" % (fstWord[0].upper(), scdWord[0].upper(), scdWord[1:], HashResult("%s%s%s" % (fstWord[0].upper(), scdWord[0].upper(), scdWord[1:]))))
            finalLoginList.append("%s%s%s \t %s" % (fstWord[0].upper(), fstWord[1:], scdWord[0].upper, HashResult("%s%s%s" % (fstWord[0].upper(), fstWord[1:], scdWord[0].upper))))

            finalLoginList.append("%s_%s \t %s" % (fstWord, scdWord, HashResult("%s_%s" % (fstWord, scdWord))))
            finalLoginList.append("%s_%s \t %s" % (fstWord[:3], scdWord, HashResult("%s_%s" % (fstWord[:3], scdWord))))
            finalLoginList.append("%s_%s \t %s" % (fstWord[0], scdWord, HashResult("%s_%s" % (fstWord[0], scdWord))))
            finalLoginList.append("%s_%s \t %s" % (fstWord, scdWord[0], HashResult("%s_%s" % (fstWord, scdWord[0]))))

            finalLoginList.append("%s-%s \t %s" % (fstWord, scdWord, HashResult("%s-%s" % (fstWord, scdWord))))
            finalLoginList.append("%s-%s \t %s" % (fstWord[:3], scdWord, HashResult("%s-%s" % (fstWord[:3], scdWord))))
            finalLoginList.append("%s-%s \t %s" % (fstWord[0], scdWord, HashResult("%s-%s" % (fstWord[0], scdWord))))
            finalLoginList.append("%s-%s \t %s" % (fstWord, scdWord[0], HashResult("%s-%s" % (fstWord, scdWord[0]))))

            finalLoginList.append("%s.%s \t %s" % (fstWord, scdWord, HashResult("%s.%s" % (fstWord, scdWord))))
            finalLoginList.append("%s.%s \t %s" % (fstWord[:3], scdWord, HashResult("%s.%s" % (fstWord[:3], scdWord))))
            finalLoginList.append("%s.%s \t %s" % (fstWord[0], scdWord, HashResult("%s.%s" % (fstWord[0], scdWord))))
            finalLoginList.append("%s.%s \t %s" % (fstWord, scdWord[0], HashResult("%s.%s" % (fstWord, scdWord[0]))))

    print("[+] Number of Login Create: %s" % (len(finalLoginList)-1))
    print("""[+] Hash create.
            |- Hexa
            |- Base64
            |- URL Encode
            |- Hash MD5
            |- Hash SHA-1
            |- Hash SHA-2.
        """)

    WriteFile(getcwd()+'\\LoginResult.txt', finalLoginList)
    print("[+] Login Write in \'LoginResult.txt\'.\n")

    # except Exception as e:
    #     print(e)
    #     print("[!] No Login Create.\nYou have a Problem.\n")

# Gen Passwoed with the word list
def GenPassword(Company):
    """
        The mix is with special char, and the word list
        :param Company: Company name
        :return: list of generated password
    """

    # add in list the list recovered by the function OpenFile
    wordPassList = ReadFile()

    # Define new list for the result
    finalPassList = []
    finalPassList.append("Password \t\t Hexa Encode \t\t\t Base64 \t\t URL Encode \t\t\t Hash MD5 \t\t\t\t\t\t Hash SHA-1 \t\t\t\t\t\t\t\t Hash SHA-256")

    try:
        # if the companyName exist then add this in the WordList
        # else continue and create list of possible password
        # finalPassList.append("")
        if Company != None:
            wordPassList.append(Company)

        for fstWord in wordPassList:
            for scdWord in wordPassList:
                # This is a list of different possible password
                # maybe epure this or add
                # ADD FinaleList                        MIX the words       CREATE HEXA BASE64 URLENCODE HASH (MD5 SHA)
                finalPassList.append("%s%s \t %s" % (fstWord, scdWord, HashResult("%s%s" % (fstWord, scdWord))))
                finalPassList.append("%s%s! \t %s" % (fstWord, scdWord, HashResult("%s%s!" % (fstWord, scdWord))))
                finalPassList.append("%s.%s \t %s" % (fstWord, scdWord, HashResult("%s.%s" % (fstWord, scdWord))))
                finalPassList.append("%s.%s! \t %s" % (fstWord, scdWord, HashResult("%s.%s!" % (fstWord, scdWord))))
                finalPassList.append("%s_%s \t %s" % (fstWord, scdWord, HashResult("%s_%s" % (fstWord, scdWord))))
                finalPassList.append("%s_%s! \t %s" % (fstWord, scdWord, HashResult("%s_%s!" % (fstWord, scdWord))))
                finalPassList.append("%s-%s \t %s" % (fstWord, scdWord, HashResult("%s-%s" % (fstWord, scdWord))))
                finalPassList.append("%s-%s! \t %s" % (fstWord, scdWord, HashResult("%s-%s!" % (fstWord, scdWord))))
                finalPassList.append("%s+%s \t %s" % (fstWord, scdWord, HashResult("%s+%s" % (fstWord, scdWord))))
                finalPassList.append("%s+%s! \t %s" % (fstWord, scdWord, HashResult("%s+%s!" % (fstWord, scdWord))))
                finalPassList.append("%s*%s \t %s" % (fstWord, scdWord, HashResult("%s*%s" % (fstWord, scdWord))))
                finalPassList.append("%s*%s \t %s" % (fstWord, scdWord, HashResult("%s*%s" % (fstWord, scdWord))))
                finalPassList.append("*%s%s \t %s" % (fstWord, scdWord, HashResult("*%s%s" % (fstWord, scdWord))))
                finalPassList.append("%s%s* \t %s" % (fstWord, scdWord, HashResult("%s%s*" % (fstWord, scdWord))))
                finalPassList.append("*%s%s* \t %s" % (fstWord, scdWord, HashResult("*%s%s*" % (fstWord, scdWord))))
                finalPassList.append("*%s*%s* \t %s" % (fstWord, scdWord, HashResult("*%s*%s*" % (fstWord, scdWord))))
                finalPassList.append("*%s*%s \t %s" % (fstWord, scdWord, HashResult("*%s*%s" % (fstWord, scdWord))))
                finalPassList.append("%s*%s* \t %s" % (fstWord, scdWord, HashResult("%s*%s*" % (fstWord, scdWord))))

                finalPassList.append("%s%s%s \t %s" % (fstWord[0].upper(), fstWord[1:], scdWord, HashResult("%s%s%s " % (fstWord[0].upper(), fstWord[1:], scdWord))))
                finalPassList.append("%s%s%s%s \t %s" % (fstWord[0].upper(), fstWord[1:], scdWord[0].upper(), scdWord[1:], HashResult("%s%s%s%s" % (fstWord[0].upper(), fstWord[1:], scdWord[0].upper(), scdWord[1:]))))
                finalPassList.append("%s%s%s! \t %s" % (fstWord, scdWord[0].upper(), scdWord[1:], HashResult("%s%s%s!" % (fstWord, scdWord[0].upper(), scdWord[1:]))))
                finalPassList.append("%s%s%s%s! \t %s" % (fstWord[0].upper(), fstWord[1:], scdWord[0].upper(), scdWord[1:], HashResult("%s%s%s%s!" % (fstWord[0].upper(), fstWord[1:], scdWord[0].upper(), scdWord[1:]))))
                finalPassList.append("%s%s.%s \t %s" % (fstWord[0].upper(), fstWord[1:], scdWord, HashResult("%s%s.%s" % (fstWord[0].upper(), fstWord[1:], scdWord))))
                finalPassList.append("%s%s.%s%s \t %s" % (fstWord[0].upper(), fstWord[1:], scdWord[0].upper(), scdWord[1:], HashResult("%s%s.%s%s" % (fstWord[0].upper(), fstWord[1:], scdWord[0].upper(), scdWord[1:]))))
                finalPassList.append("%s.%s%s! \t %s" % (fstWord, scdWord[0].upper(), scdWord[1:], HashResult("%s.%s%s!" % (fstWord, scdWord[0].upper(), scdWord[1:]))))
                finalPassList.append("%s%s.%s%s! \t %s" % (fstWord[0].upper(), fstWord[1:], scdWord[0].upper(), scdWord[1:], HashResult("%s%s.%s%s!" % (fstWord[0].upper(), fstWord[1:], scdWord[0].upper(), scdWord[1:]))))
                finalPassList.append("%s%s_%s \t %s" % (fstWord[0].upper(), fstWord[1:], scdWord, HashResult("%s%s_%s" % (fstWord[0].upper(), fstWord[1:], scdWord))))
                finalPassList.append("%s%s_%s%s \t %s" % (fstWord[0].upper(), fstWord[1:], scdWord[0].upper(), scdWord[1:], HashResult("%s%s_%s%s" % (fstWord[0].upper(), fstWord[1:], scdWord[0].upper(), scdWord[1:]))))
                finalPassList.append("%s_%s%s! \t %s" % (fstWord, scdWord[0].upper(), scdWord[1:], HashResult("%s_%s%s!" % (fstWord, scdWord[0].upper(), scdWord[1:]))))
                finalPassList.append("%s%s_%s%s! \t %s" % (fstWord[0].upper(), fstWord[1:], scdWord[0].upper(), scdWord[1:], HashResult("%s%s_%s%s!" % (fstWord[0].upper(), fstWord[1:], scdWord[0].upper(), scdWord[1:]))))
                finalPassList.append("%s%s-%s \t %s" % (fstWord[0].upper(), fstWord[1:], scdWord, HashResult("%s%s-%s" % (fstWord[0].upper(), fstWord[1:], scdWord))))
                finalPassList.append("%s%s-%s%s \t %s" % (fstWord[0].upper(), fstWord[1:], scdWord[0].upper(), scdWord[1:], HashResult("%s%s-%s%s" % (fstWord[0].upper(), fstWord[1:], scdWord[0].upper(), scdWord[1:]))))
                finalPassList.append("%s-%s%s! \t %s" % (fstWord, scdWord[0].upper(), scdWord[1:], HashResult("%s-%s%s!" % (fstWord, scdWord[0].upper(), scdWord[1:]))))
                finalPassList.append("%s%s-%s%s! \t %s" % (fstWord[0].upper(), fstWord[1:], scdWord[0].upper(), scdWord[1:], HashResult("%s%s-%s%s!" % (fstWord[0].upper(), fstWord[1:], scdWord[0].upper(), scdWord[1:]))))
                finalPassList.append("%s%s+%s! \t %s" % (fstWord[0].upper(), fstWord[1:], scdWord, HashResult("%s%s+%s!" % (fstWord[0].upper(), fstWord[1:], scdWord))))
                finalPassList.append("%s%s+%s%s! \t %s" % (fstWord[0].upper(), fstWord[1:], scdWord[0].upper(), scdWord[1:], HashResult("%s%s+%s%s!" % (fstWord[0].upper(), fstWord[1:], scdWord[0].upper(), scdWord[1:]))))
                finalPassList.append("%s+%s%s! \t %s" % (fstWord, scdWord[0].upper(), scdWord[1:], HashResult("%s+%s%s!" % (fstWord, scdWord[0].upper(), scdWord[1:]))))
                finalPassList.append("%s%s+%s%s! \t %s" % (fstWord[0].upper(), fstWord[1:], scdWord[0].upper(), scdWord[1:], HashResult("%s%s+%s%s!" % (fstWord[0].upper(), fstWord[1:], scdWord[0].upper(), scdWord[1:]))))

                finalPassList.append("%s%s*%s \t %s" % (fstWord[0].upper(), fstWord[1:], scdWord, HashResult("%s%s*%s" % (fstWord[0].upper(), fstWord[1:], scdWord))))
                finalPassList.append("%s*%s%s \t %s" % (fstWord, scdWord[0].upper(), scdWord[1:], HashResult("%s*%s%s" % (fstWord, scdWord[0].upper(), scdWord[1:]))))
                finalPassList.append("%s%s*%s%s \t %s" % (fstWord[0].upper(), fstWord[1:], scdWord[0].upper(), scdWord[1:], HashResult("%s%s*%s%s" % (fstWord[0].upper(), fstWord[1:], scdWord[0].upper(), scdWord[1:]))))
                finalPassList.append("*%s%s%s \t %s" % (fstWord[0].upper(), fstWord[1:], scdWord, HashResult("*%s%s%s" % (fstWord[0].upper(), fstWord[1:], scdWord))))
                finalPassList.append("*%s%s%s \t %s" % (fstWord, scdWord[0].upper(), scdWord[1:], HashResult("*%s%s%s" % (fstWord, scdWord[0].upper(), scdWord[1:]))))
                finalPassList.append("*%s%s%s%s \t %s" % (fstWord[0].upper(), fstWord[1:], scdWord[0].upper(), scdWord[1:], HashResult("*%s%s%s%s" % (fstWord[0].upper(), fstWord[1:], scdWord[0].upper(), scdWord[1:]))))
                finalPassList.append("%s%s%s* \t %s" % (fstWord[0].upper(), fstWord[1:], scdWord, HashResult("%s%s%s*" % (fstWord[0].upper(), fstWord[1:], scdWord))))
                finalPassList.append("%s%s%s* \t %s" % (fstWord, scdWord[0].upper(), scdWord[1:], HashResult("%s%s%s*" % (fstWord, scdWord[0].upper(), scdWord[1:]))))
                finalPassList.append("%s%s%s%s* \t %s" % (fstWord[0].upper(), fstWord[1:], scdWord[0].upper(), scdWord[1:], HashResult("%s%s%s%s*" % (fstWord[0].upper(), fstWord[1:], scdWord[0].upper(), scdWord[1:]))))
                finalPassList.append("*%s%s%s* \t %s" % (fstWord[0].upper(), fstWord[1:], scdWord, HashResult("*%s%s%s*" % (fstWord[0].upper(), fstWord[1:], scdWord))))
                finalPassList.append("*%s%s%s* \t %s" % (fstWord, scdWord[0].upper(), scdWord[1:], HashResult("*%s%s%s*" % (fstWord, scdWord[0].upper(), scdWord[1:]))))
                finalPassList.append("*%s%s%s%s* \t %s" % (fstWord[0].upper(), fstWord[1:], scdWord[0].upper(), scdWord[1:], HashResult("*%s%s%s%s*" % (fstWord[0].upper(), fstWord[1:], scdWord[0].upper(), scdWord[1:]))))
                finalPassList.append("*%s%s*%s* \t %s" % (fstWord[0].upper(), fstWord[1:], scdWord, HashResult("*%s%s*%s*" % (fstWord[0].upper(), fstWord[1:], scdWord))))
                finalPassList.append("*%s*%s%s* \t %s" % (fstWord, scdWord[0].upper(), scdWord[1:], HashResult("*%s*%s%s*" % (fstWord, scdWord[0].upper(), scdWord[1:]))))
                finalPassList.append("*%s%s*%s%s* \t %s" % (fstWord[0].upper(), fstWord[1:], scdWord[0].upper(), scdWord[1:], HashResult("*%s%s*%s%s*" % (fstWord[0].upper(), fstWord[1:], scdWord[0].upper(), scdWord[1:]))))
                finalPassList.append("*%s%s*%s \t %s" % (fstWord[0].upper(), fstWord[1:], scdWord, HashResult("*%s%s*%s" % (fstWord[0].upper(), fstWord[1:], scdWord,))))
                finalPassList.append("%s*%s%s* \t %s" % (fstWord, scdWord[0].upper(), scdWord[1:], HashResult("%s*%s%s*" % (fstWord, scdWord[0].upper(), scdWord[1:]))))
                finalPassList.append("%s%s*%s%s* \t %s" % (fstWord[0].upper(), fstWord[1:], scdWord[0].upper(), scdWord[1:], HashResult("%s%s*%s%s*" % (fstWord[0].upper(), fstWord[1:], scdWord[0].upper(), scdWord[1:]))))

        print("[+] Number of Password Create: %s" % (len(finalPassList)-1))
        print("""[+] Hash create.
                |- Hexa
                |- Base64
                |- URL Encode
                |- Hash MD5
                |- Hash SHA-1
                |- Hash SHA-2.
            """)
        
        WriteFile(getcwd()+'\\PasswordResult.txt', finalPassList)
        print("[+] Password Write in \'PasswordResult.txt\'.\n")



    except:
        print("[!] No password Create.\nYou have a Problem.\n")

# Gen Passwoed with the word list
def GenMail(Company):
    """
        The mix is with word list and famous mail box
        and the enterprise name if is precised
        :param Company: Company Name
        :return: list of generated mail
    """

    # add in list the list recovered by the function OpenFile
    wordList = ReadFile()

    # List of mail server most used
    mailList = ["@gmail.com",
                  "@aol.com",
                  "@bbox.fr",
                  "@free.fr",
                  "@emailasso.net",
                  "@gmx.fr",
                  "@gmx.com",
                  "@gmx.de",
                  "@outlook.com",
                  "@outlook.fr",
                  "@hotmail.com",
                  "@icloud.com",
                  "@laposte.net",
                  "@orange.fr",
                  "@sfr.fr",
                  "@yahoo.fr",
                  "@protonmail.com",
                  "@protonmail.ch"]

    # Define new list for the result
    finalMailList = []
    finalMailList.append("Email Address \t\t Hexa Encode \t\t\t Base64 \t\t URL Encode \t\t\t Hash MD5 \t\t\t\t\t\t Hash SHA-1 \t\t\t\t\t\t\t\t Hash SHA-256")

    try:
        if Company != None:
            mailList.append("@"+Company+".fr")
            mailList.append("@"+Company+".com")

        for fstWord in wordList:
            for mail in mailList:
                finalMailList.append("%s%s \t %s" % (fstWord, mail, HashResult("%s%s" % (fstWord, mail))))
                finalMailList.append("%s%s%s \t %s" % (fstWord[0].upper(), fstWord[1:], mail, HashResult("%s%s%s" % (fstWord[0].upper(), fstWord[1:], mail))))

            for scdWord in wordList:
                for mail in mailList:
                    finalMailList.append("%s%s%s \t %s" % (fstWord, scdWord, mail, HashResult("%s%s%s" % (fstWord, scdWord, mail))))
                    finalMailList.append("%s%s%s \t %s" % (fstWord[:3], scdWord, mail, HashResult("%s%s%s" % (fstWord[:3], scdWord, mail))))
                    finalMailList.append("%s%s%s \t %s" % (fstWord[0], scdWord, mail, HashResult("%s%s%s" % (fstWord[0], scdWord, mail))))
                    finalMailList.append("%s%s%s \t %s" % (fstWord, scdWord[0], mail, HashResult("%s%s%s" % (fstWord, scdWord[0], mail))))
                    finalMailList.append("%s%s%s \t %s" % (fstWord[:3], scdWord, mail, HashResult("%s%s%s" % (fstWord[:3], scdWord, mail))))

                    finalMailList.append("%s%s%s%s \t %s" % (fstWord, scdWord[0].upper(), scdWord[1:], mail, HashResult("%s%s%s%s" % (fstWord, scdWord[0].upper(), scdWord[1:], mail))))
                    finalMailList.append("%s%s%s%s \t %s" % (fstWord[:3], scdWord[0].upper(), scdWord[1:], mail, HashResult("%s%s%s%s" % (fstWord[:3], scdWord[0].upper(), scdWord[1:], mail))))
                    finalMailList.append("%s%s%s%s \t %s" % (fstWord[0], scdWord[0].upper(), scdWord[1:], mail, HashResult("%s%s%s%s" % (fstWord[0], scdWord[0].upper(), scdWord[1:], mail))))
                    finalMailList.append("%s%s%s \t %s" % (fstWord, scdWord[0].upper(), mail, HashResult("%s%s%s" % (fstWord, scdWord[0].upper(), mail))))

                    finalMailList.append("%s%s%s%s \t %s" % (fstWord[0].upper(), fstWord[1:], scdWord, mail, HashResult("%s%s%s%s" % (fstWord[0].upper(), fstWord[1:], scdWord, mail))))
                    finalMailList.append("%s%s%s%s \t %s" % (fstWord[0].upper(), fstWord[1:3], scdWord, mail, HashResult("%s%s%s%s" % (fstWord[0].upper(), fstWord[1:3], scdWord, mail))))
                    finalMailList.append("%s%s%s \t %s" % (fstWord[0].upper(), scdWord, mail, HashResult("%s%s%s" % (fstWord[0].upper(), scdWord, mail))))
                    finalMailList.append("%s%s%s%s \t %s" % (fstWord[0].upper(), fstWord[1:], scdWord[0], mail, HashResult("%s%s%s%s" % (fstWord[0].upper(), fstWord[1:], scdWord[0], mail))))

                    finalMailList.append("%s%s%s%s%s \t %s" % (fstWord[0].upper(), fstWord[1:], scdWord[0].upper(), scdWord[1:], mail, HashResult("%s%s%s%s%s" % (fstWord[0].upper(), fstWord[1:], scdWord[0].upper(), scdWord[1:], mail))))
                    finalMailList.append("%s%s%s%s \t %s" % (fstWord[0].upper(), fstWord[1:3], scdWord[1:], mail, HashResult("%s%s%s%s" % (fstWord[0].upper(), fstWord[1:3], scdWord[1:], mail))))
                    finalMailList.append("%s%s%s%s \t %s" % (fstWord[0].upper(), scdWord[0].upper(), scdWord[1:], mail, HashResult("%s%s%s%s" % (fstWord[0].upper(), scdWord[0].upper(), scdWord[1:], mail))))
                    finalMailList.append("%s%s%s%s \t %s" % (fstWord[0].upper(), fstWord[1:], scdWord[0].upper, mail, HashResult("%s%s%s%s" % (fstWord[0].upper(), fstWord[1:], scdWord[0].upper, mail))))

                    finalMailList.append("%s_%s%s \t %s" % (fstWord, scdWord, mail, HashResult("%s_%s%s" % (fstWord, scdWord, mail))))
                    finalMailList.append("%s_%s%s \t %s" % (fstWord[:3], scdWord, mail, HashResult("%s_%s%s" % (fstWord[:3], scdWord, mail))))
                    finalMailList.append("%s_%s%s \t %s" % (fstWord[0], scdWord, mail, HashResult("%s_%s%s" % (fstWord[0], scdWord, mail))))
                    finalMailList.append("%s_%s%s \t %s" % (fstWord, scdWord[0], mail, HashResult("%s_%s%s" % (fstWord, scdWord[0], mail))))

                    finalMailList.append("%s-%s%s \t %s" % (fstWord, scdWord, mail, HashResult("%s-%s%s" % (fstWord, scdWord, mail))))
                    finalMailList.append("%s-%s%s \t %s" % (fstWord[:3], scdWord, mail, HashResult("%s-%s%s" % (fstWord[:3], scdWord, mail))))
                    finalMailList.append("%s-%s%s \t %s" % (fstWord[0], scdWord, mail, HashResult("%s-%s%s" % (fstWord[0], scdWord, mail))))
                    finalMailList.append("%s-%s%s \t %s" % (fstWord, scdWord[0], mail, HashResult("%s-%s%s" % (fstWord, scdWord[0], mail))))

                    finalMailList.append("%s.%s%s \t %s" % (fstWord, scdWord, mail, HashResult("%s.%s%s" % (fstWord, scdWord, mail))))
                    finalMailList.append("%s.%s%s \t %s" % (fstWord[:3], scdWord, mail, HashResult("%s.%s%s" % (fstWord[:3], scdWord, mail))))
                    finalMailList.append("%s.%s%s \t %s" % (fstWord[0], scdWord, mail, HashResult("%s.%s%s" % (fstWord[0], scdWord, mail))))
                    finalMailList.append("%s.%s%s \t %s" % (fstWord, scdWord[0], mail, HashResult("%s.%s%s" % (fstWord, scdWord[0], mail))))

        print("[+] Number of Email Address Create: %s" % (len(finalMailList)-1))
        print("""[+] Hash create.
                        |- Hexa
                        |- Base64
                        |- URL Encode
                        |- Hash MD5
                        |- Hash SHA-1
                        |- Hash SHA-2.
                    """)

        WriteFile(getcwd()+'\\EmailResult.txt', finalMailList)
        print("[+] Email Write in \'EmailResult.txt\'.\n")



    except:
        print("[!] No Email Create.\nYou have a Problem.\n")


# Helper message
def Help():
    print("""Usage: OhMyGenerator -l | -p | -m [-e companyName]
            Description:
                    IceGenerator is a Generator of Login, Password and Email Address.
                    You Write in file \'OhMyWordList.txt\' a list of word.
                    This list used to Generate a Login, Password, Email.
                    The result are create in \'LoginResult.txt\', \'PasswordResult.txt\', \'EmailResult.txt\'.

            Arguments:
                    -l      Generate Login from the Word List.
                    -p      Generate Password from the Word List.
                    -m      Generate Mail from the Word List.
                    -e      Used to generate more password and mail
                            if is precised in command line.
                            if the name is in many word then add \"\"

                            Developed By Icenuke.
            """)


"""
    Main code with the check of args and extern file
"""
if __name__ == "__main__":
    print("""
   
        ___  _    __  __       ___                       _           
       / _ \| |_ |  \/  |_  _ / __|___ _ _  ___ _ _ __ _| |_ ___ _ _ 
      | (_) | ' \| |\/| | || | (_ / -_) ' \/ -_) '_/ _` |  _/ _ \ '_|
       \___/|_||_|_|  |_|\_, |\___\___|_||_\___|_| \__,_|\__\___/_|  
                        |__/                Developed by Icenuke.

    """)

    try:
        if "-l" in argv and "-p" in argv and "-m" in argv and "-e" in argv:
            if len(argv[int(argv.index("-e")+1)]) > 0:
                GenLogin()
                GenPassword(argv[int(argv.index("-e")+1)])
                GenMail(argv[int(argv.index("-e")+1)])

        elif "-l" in argv and "-p" in argv and "-m" in argv:
            GenLogin()
            GenPassword(None)
            GenMail(None)

        elif "-l" in argv and "-p" in argv and "-e" in argv:
            if len(argv[int(argv.index("-e") + 1)]) > 0:
                GenLogin()
                GenPassword(argv[int(argv.index("-e")+1)])

        elif "-l" in argv and "-p" in argv:
            GenLogin()
            GenPassword(None)

        elif "-l" in argv and "-m" in argv and "-e" in argv:
            if len(argv[int(argv.index("-e") + 1)]) > 0:
                GenLogin()
                GenMail(argv[int(argv.index("-e")+1)])

        elif "-l" in argv and "-m" in argv:
            GenLogin()
            GenMail(None)

        elif "-p" in argv and "-m" in argv and "-e" in argv:
            if len(argv[int(argv.index("-e") + 1)]) > 0:
                GenPassword(argv[int(argv.index("-e")+1)])
                GenMail(argv[int(argv.index("-e")+1)])

        elif "-p" in argv and "-m" in argv:
            GenPassword(None)
            GenMail(None)

        elif "-l" in argv:
            GenLogin()

        elif "-p" in argv and "-e" in argv:
            if len(argv[int(argv.index("-e") + 1)]) > 0:
                GenPassword(argv[int(argv.index("-e")+1)])

        elif "-p" in argv:
            GenPassword(None)

        elif "-m" in argv and "-e" in argv:
            if len(argv[int(argv.index("-e") + 1)]) > 0:
                GenMail(argv[int(argv.index("-e")+1)])

        elif "-m" in argv:
            GenMail(None)

        else:
            Help()

    except:
         Help()
