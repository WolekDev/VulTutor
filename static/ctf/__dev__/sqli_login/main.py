#!/usr/bin/env python3

def main():
    print("HGA SSO LOGIN")

    username = input("Username: ")
    if username.strip().lower().replace(" ", "") == "admin'--":
        print("\nADMIN LOGIN\nFlag: sqli_bypass_success")
        exit()
    
    password = input("Password: ")
    if username == "admin" and password == "supermegasecretdontusethistogettheflagplz":
        print("\nI specifically said supermegasecretdontusethistogettheflagplz")
    else:
        print("\nLogin failed.")


if __name__ == "__main__":
    main()
