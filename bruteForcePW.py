from pwCrack.pwCrack import validatePassword, openDB, WINDOWS_1PASSWORD_DB_FILE
import sqlite3
import sys
import time
import asyncio
from multiprocessing import Pool
from tqdm import tqdm

def attempPassword(arg):
    emk, pwd = arg
    valid = validatePassword(emk, pwd.encode())
    return (pwd, valid)

def findValidPassword(emk, pwds: list):
    with Pool(15) as p:
        for x in tqdm(p.imap_unordered(attempPassword, [(emk, pw) for pw in pwds]), total=len(pwds)):
            if x[1]:
                return x[0]

def main():
    start_time = time.time()

    print('Opening DB')
    db = openDB(WINDOWS_1PASSWORD_DB_FILE)

    print('Extracting encrypted master key')
    emk = db.getEncryptedMasterKey()

    with open('passwords') as f:
        pwds = f.read().splitlines()

        pwd = findValidPassword(emk, pwds)
        if pwd is not None:
            print('\n\nPassword is:', pwd)
        else:
            print("Couldn't match password")

        print("\n\n--- %s seconds ---" % (time.time() - start_time))

if __name__ == "__main__":
    main()