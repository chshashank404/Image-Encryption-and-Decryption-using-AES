import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image
from Cryptodome.Cipher import AES
import numpy as np

def encryptImage():
    imagePath = imageInput_encrypt.get()
    outputImagePath = outputImageInput_encrypt.get()
    key = getKeyInput(keyInput_encrypt)

    img = Image.open(imagePath)
    imgArray = np.array(img)
    imgFlat = imgArray.flatten()
    cipher = AES.new(key, AES.MODE_CBC)
    encryptedData = cipher.encrypt(imgFlat.tobytes())
    encryptedImageArray = np.frombuffer(encryptedData, dtype=np.uint8).reshape(imgArray.shape)
    encryptedImg = Image.fromarray(encryptedImageArray)
    encryptedImg.save(outputImagePath)
    messagebox.showinfo("Encryption", "Image encrypted!")

def decryptImage():
    encryptedImagePath = imageInput_decrypt.get()
    outputImagePath = outputImageInput_decrypt.get()
    key = getKeyInput(keyInput_decrypt)

    encryptedImg = Image.open(encryptedImagePath)
    encryptedImageArray = np.array(encryptedImg)
    encryptedFlat = encryptedImageArray.flatten()
    cipher = AES.new(key, AES.MODE_CBC)
    decryptedData = cipher.decrypt(encryptedFlat.tobytes())
    decryptedImageArray = np.frombuffer(decryptedData, dtype=np.uint8).reshape(encryptedImageArray.shape)
    decryptedImg = Image.fromarray(decryptedImageArray)
    decryptedImg.save(outputImagePath)
    messagebox.showinfo("Decryption", "Image decrypted!")

def getKeyInput(keyInput):
    keyString = keyInput.get()
    try:
        keyList = [int(x) for x in keyString.split()]

        # Modify this condition for different key lengths
        if len(keyList) > 32:  # For 256-bit keys
            raise ValueError("Key Length Must Not Exceed 32!")

        key = bytearray(keyList)
        while len(key) < 32:  # Change to 16 or 24 if needed
            key.append(0)
        return bytes(key)
    except ValueError as e:
        messagebox.showerror("Invalid Key", "Please Enter Up to 32 Numbers Only!") 
        return None


def browseImage(inputField):
    filePath = filedialog.askopenfilename()
    inputField.delete(0, tk.END)
    inputField.insert(0, filePath)

def browseOutputImage(outputField):
    filePath = filedialog.asksaveasfilename(defaultextension=".png")
    outputField.delete(0, tk.END)
    outputField.insert(0, filePath)

root = tk.Tk()
root.title("Image Encryption and Decryption using AES")
root.geometry("760x400")
root.configure(bg="#63ba00")

encryption_frame = tk.LabelFrame(root, text="Encryption", padx=10, pady=10, fg="white", bg="#63ba00", font=("Helvetica", 12, "bold"))
encryption_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

tk.Label(encryption_frame, text="Image Input Path", fg="white", bg="#63ba00", font=("Helvetica", 10, "bold")).grid(row=0, column=0)

imageInput_encrypt = tk.Entry(encryption_frame, width=30)
imageInput_encrypt.grid(row=0, column=1)
tk.Button(encryption_frame, text="Browse", command=lambda: browseImage(imageInput_encrypt), bg="#5700BA", fg="white").grid(row=0, column=2)

tk.Label(encryption_frame, text="Output Image Path", fg="white", bg="#63ba00", font=("Helvetica", 10, "bold")).grid(row=1, column=0)
outputImageInput_encrypt = tk.Entry(encryption_frame, width=30)
outputImageInput_encrypt.grid(row=1, column=1, padx=10)  # Add padding to the Entry field
tk.Button(encryption_frame, text="Browse", command=lambda: browseOutputImage(outputImageInput_encrypt), bg="#5700BA", fg="white").grid(row=1, column=2, padx=10, pady=4)  # Add padding to the Button

tk.Label(encryption_frame, text="Encryption Key (Max Length Is 32, Separated By Spaces)", fg="white", bg="#63ba00", font=("Helvetica", 10, "bold")).grid(row=2, column=0, pady=8)
keyInput_encrypt = tk.Entry(encryption_frame, width=30)
keyInput_encrypt.grid(row=2, column=1)
tk.Button(encryption_frame, text="Encrypt", command=encryptImage, bg="#A9C92D", fg="white").grid(row=3, column=1)

separator = tk.Frame(root, height=2, bd=1, relief=tk.SUNKEN)
separator.grid(row=1, column=0, sticky="ew", padx=10, pady=10)

decryption_frame = tk.LabelFrame(root, text="Decryption", padx=10, pady=10, fg="white", bg="#63ba00", font=("Helvetica", 12, "bold"))
decryption_frame.grid(row=2, column=0, padx=10, pady=10, sticky="nsew")

tk.Label(decryption_frame, text="Encrypted Image Path", fg="white", bg="#63ba00", font=("Helvetica", 10, "bold")).grid(row=0, column=0)
imageInput_decrypt = tk.Entry(decryption_frame, width=30)
imageInput_decrypt.grid(row=0, column=1)
tk.Button(decryption_frame, text="Browse", command=lambda: browseImage(imageInput_decrypt), bg="#5700BA", fg="white").grid(row=0, column=2)

tk.Label(decryption_frame, text="Output Image Path", fg="white", bg="#63ba00", font=("Helvetica", 10, "bold")).grid(row=1, column=0)
outputImageInput_decrypt = tk.Entry(decryption_frame, width=30)
outputImageInput_decrypt.grid(row=1, column=1, padx=10)  # Add padding to the Entry field
tk.Button(decryption_frame, text="Browse", command=lambda: browseOutputImage(outputImageInput_decrypt), bg="#5700BA", fg="white").grid(row=1, column=2, padx=10, pady=4)  # Add padding to the Button

tk.Label(decryption_frame, text="Decryption Key (Max Length Is 32, Separated By Spaces)", fg="white", bg="#63ba00", font=("Helvetica", 10, "bold")).grid(row=2, column=0)
keyInput_decrypt = tk.Entry(decryption_frame, width=30)
keyInput_decrypt.grid(row=2, column=1)
tk.Button(decryption_frame, text="Decrypt", command=decryptImage, bg="#FF5733", fg="white").grid(row=3, column=1, pady=7)

root.mainloop()