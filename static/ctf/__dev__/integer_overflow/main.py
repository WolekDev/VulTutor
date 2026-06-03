#!/usr/bin/env python3

def main():
    print("Game: GTA 6")
    print("Release Date: 31/11/2026")

    while True:
        choice = input("Name your price (50 zl or more): ")
        try:
            price = int(choice)
        except ValueError:
            print("Invalid price, please enter a number.")
            continue

        if price < 50:
            print("The store requires a minimum price of 50 zl.")
            continue

        wrapped = price % 65536

        if wrapped == 0:
            print("\n!!!CONGRATULATION!!!\nFree Game Claimed\nFlag: yay_free_gta6")
        else:
            print(f"\nPayment amount : {wrapped} zl")
        break


if __name__ == "__main__":
    main()
