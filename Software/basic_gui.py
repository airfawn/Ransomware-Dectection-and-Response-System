#!/usr/bin/env python3
import tkinter as tk


def main():
    root = tk.Tk()
    root.title("RDRS Basic GUI")
    root.geometry("320x180")

    label = tk.Label(root, text="RDRS GUI Window", font=("Arial", 14))
    label.pack(pady=20)

    info = tk.Label(root, text="This is a separate GUI script.")
    info.pack(pady=10)

    close_button = tk.Button(root, text="Close", command=root.destroy)
    close_button.pack(pady=10)

    root.mainloop()


if __name__ == "__main__":
    main()
