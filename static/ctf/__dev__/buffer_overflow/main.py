#!/usr/bin/env python3

def main():
    print("Goodronka Self Checkout")

    # Simulate a C-like frame with 5 slots: 4 items + user id
    item_ids = [0, 0, 0, 0, 5]
    count = 0

    while True:
        if count >= 5:
            break

        choice = input("Item ID to buy (Max items 4) (f to finish): ")
        if choice.lower() == "f":
            break

        try:
            item = int(choice)
        except ValueError:
            print("Invalid Item ID, please enter a number or f to finish.")
            continue

        if count < 4:
            item_ids[count] = item
        else:
            # 5th input overwrites the user id slot
            item_ids[4] = item
        count += 1

    total = sum(item_ids[:4])
    user_id = item_ids[4]

    if user_id == 0:
        print("\nUser ID: 0 \nOpening admin dashboard...\nADMIN DASHBOARD\nFlag: admin_dashboard_secret")
    else:
        print(f"\nUser ID: {user_id}\n Total: 60 zl")


if __name__ == "__main__":
    main()
