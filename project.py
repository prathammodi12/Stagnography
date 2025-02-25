import cv2
import os
import numpy as np
import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk

stored_msg = ""  # ✅ Initialize global variable

# ---------------- Encryption Function ---------------- #
def encode_message(img, msg, password):
    """Encodes the message into the image using LSB steganography"""
    msg += "####"  # End of message delimiter
    binary_msg = ''.join(format(ord(char), '08b') for char in msg)
    binary_pass = ''.join(format(ord(char), '08b') for char in password)
    
    rows, cols, _ = img.shape
    max_size = rows * cols * 3

    if len(binary_msg) + len(binary_pass) > max_size:
        messagebox.showerror("Error", "Message too long for this image.")
        return None

    data = binary_pass + binary_msg  # Embed password first
    idx = 0

    for row in range(rows):
        for col in range(cols):
            for channel in range(3):
                if idx < len(data):
                    img[row, col, channel] = (img[row, col, channel] & 254) | int(data[idx])
                    idx += 1
                else:
                    return img
    return img

# ---------------- Decryption Function ---------------- #
def decode_message(img, password):
    """Decodes the hidden message from the image"""
    binary_data = ""
    
    for row in range(img.shape[0]):
        for col in range(img.shape[1]):
            for channel in range(3):
                binary_data += str(img[row, col, channel] & 1)

    # Extract password first
    password_length = len(password) * 8
    extracted_pass = ''.join(chr(int(binary_data[i:i+8], 2)) for i in range(0, password_length, 8))
    
    if extracted_pass != password:
        return "Invalid Password!"

    # Extract message after password
    binary_msg = binary_data[password_length:]
    message = ""

    for i in range(0, len(binary_msg), 8):
        char = chr(int(binary_msg[i:i+8], 2))
        if message[-4:] == "####":  # Stop at delimiter
            return message[:-4]
        message += char

    return "No Hidden Message Found!"

# ---------------- GUI Functions ---------------- #
def select_image():
    """Opens a file dialog to select an image"""
    file_path = filedialog.askopenfilename(filetypes=[("Image Files", "*.png;*.jpg;*.jpeg")])
    if not file_path:
        return
    
    img = Image.open(file_path)
    img.thumbnail((250, 250))
    img = ImageTk.PhotoImage(img)

    lbl_image.config(image=img)
    lbl_image.image = img
    lbl_image.path = file_path

def process():
    """Processes the selected operation (encryption or decryption)"""
    if not hasattr(lbl_image, "path"):
        messagebox.showwarning("Warning", "Select an image first!")
        return
    
    password = entry_pass.get().strip()
    if not password:
        messagebox.showwarning("Warning", "Enter password!")
        return

    img = cv2.imread(lbl_image.path)

    if operation.get() == "encrypt":
        msg = entry_msg.get().strip()
        if not msg:
            messagebox.showwarning("Warning", "Enter a message for encryption!")
            return
        
        encoded_img = encode_message(img, msg, password)
        if encoded_img is not None:
            save_path = "encryptedImage.png"
            cv2.imwrite(save_path, encoded_img)
            os.system(f"start {save_path}")
            messagebox.showinfo("Success", "Message encrypted successfully!")
    
    elif operation.get() == "decrypt":
        message = decode_message(img, password)
        messagebox.showinfo("Decrypted Message", message)

def toggle_fields():
    """Toggles input fields based on selected operation while preserving message text"""
    global stored_msg

    if operation.get() == "encrypt":
        entry_msg.delete(0, tk.END)  # Clear field before restoring
        entry_msg.insert(0, stored_msg)  # ✅ Restore previously entered message
        lbl_msg.pack()
        entry_msg.pack(pady=5)
        btn_process.config(text="Encrypt & Save", bg="green")

    else:  # Switching to Decryption
        stored_msg = entry_msg.get()  # ✅ Store message before hiding
        lbl_msg.pack_forget()
        entry_msg.pack_forget()
        btn_process.config(text="Decrypt", bg="blue")

# ---------------- GUI Setup ---------------- #
root = tk.Tk()
root.title("Image Steganography")
root.geometry("400x500")

# Operation Selection
operation = tk.StringVar(value="encrypt")

frame_radio = tk.Frame(root)
frame_radio.pack(pady=5)

tk.Radiobutton(frame_radio, text="Encrypt", variable=operation, value="encrypt", command=toggle_fields).pack(side=tk.LEFT, padx=10)
tk.Radiobutton(frame_radio, text="Decrypt", variable=operation, value="decrypt", command=toggle_fields).pack(side=tk.LEFT, padx=10)

# Image Selection
lbl_image = tk.Label(root, text="No Image Selected", width=25, height=10, relief="solid")
lbl_image.pack(pady=10)

btn_select = tk.Button(root, text="Select Image", command=select_image)
btn_select.pack()

# Message Entry
lbl_msg = tk.Label(root, text="Enter Message:")
lbl_msg.pack()
entry_msg = tk.Entry(root, width=40)
entry_msg.pack(pady=5)

# Password Entry
tk.Label(root, text="Enter Password:").pack()
entry_pass = tk.Entry(root, width=40, show="*")
entry_pass.pack(pady=5)

# Process Button
btn_process = tk.Button(root, text="Encrypt & Save", command=process, bg="green", fg="white")
btn_process.pack(pady=5)

# Initialize correct field visibility
toggle_fields()

root.mainloop()
