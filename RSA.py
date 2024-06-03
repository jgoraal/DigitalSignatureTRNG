import tkinter as tk
from tkinter import messagebox, filedialog
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA3_256
import os
import cv2
import numpy as np


# Generate random bits from images (TRNG function)
def generate_random_bits_from_images(image_folder, num_needed):
    image_files = [os.path.join(image_folder, f) for f in os.listdir(image_folder) if
                   f.endswith(('png', 'jpg', 'jpeg'))]
    final_list = []
    num_so_far = 0

    for i, image_file in enumerate(image_files):
        if num_so_far >= num_needed:
            break

        image = cv2.imread(image_file, cv2.IMREAD_GRAYSCALE)
        if image is None:
            continue

        image = image.flatten()
        valid_pixels = image[(image >= 3) & (image <= 252)]
        sublist = np.bitwise_and(valid_pixels, 1)
        if i % 2 == 0:
            sublist = np.bitwise_xor(sublist, 1)

        bits_needed = num_needed - num_so_far
        if len(sublist) > bits_needed:
            sublist = sublist[:bits_needed]

        final_list.extend(sublist)
        num_so_far += len(sublist)

        # Print debug information
        print(f"Processed {i + 1}/{len(image_files)} images, generated {num_so_far}/{num_needed} bits so far.")

        if num_so_far >= num_needed:
            break

    print(f"Random bits generated.")
    return final_list


# Convert bits to bytes
def bits_to_bytes(bits):
    byte_array = bytearray()
    for i in range(0, len(bits), 8):
        byte = ''.join(map(str, bits[i:i + 8]))
        if len(byte) == 8:
            byte_array.append(int(byte, 2))
    return bytes(byte_array)


# Generate random data for the RNG
def my_rng(size):
    global bit_index, random_bits

    bits_needed = size * 8  # Calculate the number of bits needed

    if bit_index + bits_needed > len(random_bits):
        raise ValueError("Not enough random bits available")  # Check if there are enough random bits available

    bits = random_bits[bit_index:bit_index + bits_needed]  # Get the required bits
    bit_index += bits_needed  # Update the bit index

    return bits_to_bytes(bits)  # Convert bits to bytes and return


# Generate RSA keys
def generate_keys():
    global private_key, public_key

    key = RSA.generate(2048, randfunc=my_rng)  # Generate RSA key pair using custom RNG
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    with open("private.pem", "wb") as priv_file:
        priv_file.write(private_key)  # Save the private key to a file

    with open("public.pem", "wb") as pub_file:
        pub_file.write(public_key)  # Save the public key to a file

    messagebox.showinfo("Success", "RSA keys generated and saved to files.")  # Show success message


# Sign the message
def sign_message():
    global signature

    message = message_entry.get().strip()  # Get the message from the entry

    if not message:
        messagebox.showerror("Error", "Message cannot be empty.")
        return

    message_bytes = message.encode('utf-8')  # Encode the message to bytes
    hash_obj = SHA3_256.new(message_bytes)  # Create a SHA3_256 hash of the message
    private_key_obj = RSA.import_key(private_key)  # Import the private key

    signature = pkcs1_15.new(private_key_obj).sign(hash_obj)  # Sign the hash with the private key

    messagebox.showinfo("Success", "Message signed.")


# Verify the signature of the message
def verify_signature():
    message = message_entry.get().strip().encode('utf-8')  # Get the message and encode to bytes
    hash_obj = SHA3_256.new(message)  # Create a SHA3_256 hash of the message
    public_key_obj = RSA.import_key(public_key)  # Import the public key

    try:
        pkcs1_15.new(public_key_obj).verify(hash_obj, signature)  # Verify the signature
        messagebox.showinfo("Success", "Signature is valid.")
    except (ValueError, TypeError):
        messagebox.showerror("Error", "Signature is invalid.")


# Sign a file
def sign_file():
    file_path = filedialog.askopenfilename()  # Open a dialog to select a file
    if not file_path:
        return

    with open(file_path, "rb") as file:
        file_data = file.read()

    hash_obj = SHA3_256.new(file_data)  # Create a SHA3_256 hash of the file data
    private_key_obj = RSA.import_key(private_key)  # Import the private key

    signature = pkcs1_15.new(private_key_obj).sign(hash_obj)  # Sign the hash with the private key

    with open(file_path + ".sig", "wb") as sig_file:
        sig_file.write(signature)

    messagebox.showinfo("Success", "File signed and signature saved.")


# Verify the signature of a file
def verify_file_signature():
    file_path = filedialog.askopenfilename()  # Open a dialog to select a file
    if not file_path:
        return

    sig_path = filedialog.askopenfilename(title="Select Signature File")  # Open a dialog to select the signature file
    if not sig_path:
        return

    with open(file_path, "rb") as file:
        file_data = file.read()

    with open(sig_path, "rb") as sig_file:
        signature = sig_file.read()

    hash_obj = SHA3_256.new(file_data)  # Create a SHA3_256 hash of the file data
    public_key_obj = RSA.import_key(public_key)  # Import the public key

    try:
        pkcs1_15.new(public_key_obj).verify(hash_obj, signature)  # Verify the signature
        messagebox.showinfo("Success", "File signature is valid.")
    except (ValueError, TypeError):
        messagebox.showerror("Error", "File signature is invalid.")


# Generate TRNG bits
def generate_trng_bits():
    global random_bits, bit_index

    folder_selected = filedialog.askdirectory()  # Open a dialog to select a folder
    if not folder_selected:
        messagebox.showerror("Error", "No folder selected.")
        return

    num_needed = 10000000  # Number of bits needed
    random_bits = generate_random_bits_from_images(folder_selected, num_needed)  # Generate random bits
    bit_index = 0  # Reset bit index
    messagebox.showinfo("Success", "Random bits generated!")


# Set up the GUI
def setup_gui():
    global message_entry

    root = tk.Tk()
    root.title("RSA Key Generation and Signing")

    frame = tk.Frame(root)
    frame.pack(pady=20, padx=20)

    generate_trng_button = tk.Button(frame, text="Generate TRNG Bits", command=generate_trng_bits)
    generate_trng_button.grid(row=0, column=0, pady=10)

    generate_button = tk.Button(frame, text="Generate RSA Keys", command=generate_keys)
    generate_button.grid(row=1, column=0, pady=10)

    message_label = tk.Label(frame, text="Message:")
    message_label.grid(row=2, column=0, pady=10)

    message_entry = tk.Entry(frame, width=50)
    message_entry.grid(row=2, column=1, pady=10)

    sign_button = tk.Button(frame, text="Sign Message", command=sign_message)
    sign_button.grid(row=3, column=0, pady=10)

    verify_button = tk.Button(frame, text="Verify Signature", command=verify_signature)
    verify_button.grid(row=3, column=1, pady=10)

    sign_file_button = tk.Button(frame, text="Sign File", command=sign_file)
    sign_file_button.grid(row=4, column=0, pady=10)

    verify_file_button = tk.Button(frame, text="Verify File Signature", command=verify_file_signature)
    verify_file_button.grid(row=4, column=1, pady=10)

    root.mainloop()


# Initialize random bits for the first time
random_bits = []
bit_index = 0
signature = None
private_key = None
public_key = None

setup_gui()
