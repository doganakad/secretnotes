from tkinter import *
from tkinter import messagebox

from cryptography.fernet import Fernet
import base64

#GUI Setup
window = Tk()
window.title("Secret Notes")
window.config(padx=30, pady=30)

image = PhotoImage(file="topsecret.png")
smaller_image = image.subsample(4, 4)
image_label = Label(image=smaller_image)
image_label.pack()

#Title Input
title_input_label = Label(text="Enter your Title")
title_input_label.pack()
title_input = Entry(width=60)
title_input.pack()

#Secret Input
secret_input_label = Label(text="Enter your secret")
secret_input_label.pack()
secret_input = Text()
secret_input.pack()

#Master Key Input
master_input_label = Label(text="Enter master key")
master_input_label.pack()
master_input = Entry(width=60)
master_input.pack()

# Function to Derive a Valid Key from User Input
def derive_key(password: str):
    """Generate a 32-byte base64-encoded Fernet key from a password."""
    key = base64.urlsafe_b64encode(password.ljust(32).encode()[:32])
    return key

#Encrypt and Save Secret
def write_file():
    title = title_input.get()
    secret = secret_input.get("1.0", END)
    master_key = master_input.get()

    if not master_key or not secret or not title:
        messagebox.showerror("showerror", "Please enter all information.")

    else:
        try:
            #Convert password into a valid Fernet key
            key = derive_key(master_key)
            fernet = Fernet(key)

            encMessage = fernet.encrypt(secret.encode())

            # Save to file
            with open("mysecret.txt", "a") as myNewFile:
                myNewFile.write(f"{title}\n")
                myNewFile.write(f"{encMessage.decode()}\n")

            title_input.delete(0,END)
            secret_input.delete(1.0,END)
            master_input.delete(0,END)
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")

#Decrypt the saved message
def decrypt_message():
    secret = secret_input.get("1.0", END)
    master_key = master_input.get()

    if not master_key or not secret:
        messagebox.showerror("showerror", "Please enter all information.")
    else:
        key = derive_key(master_key)
        fernet = Fernet(master_key)

        # Decrypt message
        decMessage = fernet.decrypt(secret).decode()

        # Clear the text box and insert decrypted text
        secret_input.delete(1.0, END)
        secret_input.insert(1.0, decMessage)

#Buttons
encrypt_button = Button(text="Save & Encrypt",command=write_file)
encrypt_button.pack()

decrypt_button = Button(text="Decrypt",command=decrypt_message)
decrypt_button.pack()

window.mainloop()