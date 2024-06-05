import tkinter as tk
from tkinter import messagebox, filedialog
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA3_256
import os
import cv2
import numpy as np

# Define global variables
random_bits = []
bit_index = 0
signature = None
signature_file = None
private_key = None
public_key = None
file_to_verify_path = None
key_path = None
save_dir = os.getcwd()


# Generate random bits from images (TRNG function)
def generate_random_bits_from_images(image_folder, num_needed):
    try:
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

            additional_entropy = np.frombuffer(os.urandom(len(sublist)), dtype=np.uint8) % 2
            sublist = np.bitwise_xor(sublist, additional_entropy)

            bits_needed = num_needed - num_so_far
            if len(sublist) > bits_needed:
                sublist = sublist[:bits_needed]

            final_list.extend(sublist)
            num_so_far += len(sublist)

        return final_list

    except Exception as e:
        messagebox.showerror("Error", f"Failed to generate random bits: {str(e)}")
        return []


# Convert bits to bytes
def bits_to_bytes(bits):
    try:
        byte_array = bytearray()
        for i in range(0, len(bits), 8):
            byte = ''.join(map(str, bits[i:i + 8]))
            if len(byte) == 8:
                byte_array.append(int(byte, 2))
        return bytes(byte_array)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to convert bits to bytes: {str(e)}")
        return b''


# Generate random data for the RNG
def my_rng(size):
    global bit_index, random_bits

    try:
        bits_needed = size * 8  # Calculate the number of bits needed

        if bit_index + bits_needed > len(random_bits):
            raise ValueError("Not enough random bits available")  # Check if there are enough random bits available

        bits = random_bits[bit_index:bit_index + bits_needed]  # Get the required bits
        bit_index += bits_needed  # Update the bit index

        return bits_to_bytes(bits)  # Convert bits to bytes and return
    except Exception as e:
        messagebox.showerror("Error", f"Failed to generate random data: {str(e)}")
        return b''


# Generate RSA keys
def generate_keys():
    global private_key, public_key, save_dir

    try:
        key = RSA.generate(2048, randfunc=my_rng)  # Generate RSA key pair using custom RNG
        private_key = key.export_key()
        public_key = key.publickey().export_key()

        save_dir = filedialog.askdirectory(title="Select Directory to Save Keys")  # Ask user to select save directory
        if not save_dir:
            status_label.config(text="Error: No directory selected.")
            messagebox.showerror("Error", "No directory selected.")
            return

        with open(os.path.join(save_dir, "private.pem"), "wb") as priv_file:
            priv_file.write(private_key)  # Save the private key to a file

        with open(os.path.join(save_dir, "public.pem"), "wb") as pub_file:
            pub_file.write(public_key)  # Save the public key to a file

        status_label.config(text="RSA keys generated and saved to files.")
        messagebox.showinfo("Success", "RSA keys generated and saved to files.")  # Show success message
        enable_buttons([sign_message_button, sign_file_button])
        update_interface()
    except Exception as e:
        messagebox.showerror("Error", f"Failed to generate RSA keys: {str(e)}")


# Sign the message
def sign_message():
    global signature

    try:
        message = message_entry.get().strip()  # Get the message from the entry

        if not message:
            status_label.config(text="Error: Message cannot be empty.")
            messagebox.showerror("Error", "Message cannot be empty.")
            return

        message_bytes = message.encode('utf-8')  # Encode the message to bytes
        hash_obj = SHA3_256.new(message_bytes)  # Create a SHA3_256 hash of the message
        private_key_obj = RSA.import_key(private_key)  # Import the private key

        signature = pkcs1_15.new(private_key_obj).sign(hash_obj)  # Sign the hash with the private key

        status_label.config(text="Message signed.")
        messagebox.showinfo("Success", "Message signed.")
        enable_buttons([verify_message_button])
    except Exception as e:
        messagebox.showerror("Error", f"Failed to sign message: {str(e)}")


# Verify the signature of the message
def verify_message():
    try:
        message = message_entry.get().strip().encode('utf-8')  # Get the message and encode to bytes
        hash_obj = SHA3_256.new(message)  # Create a SHA3_256 hash of the message
        public_key_obj = RSA.import_key(public_key)  # Import the public key

        pkcs1_15.new(public_key_obj).verify(hash_obj, signature)  # Verify the signature
        status_label.config(text="Signature is valid.")
        messagebox.showinfo("Success", "Signature is valid.")
    except (ValueError, TypeError) as e:
        status_label.config(text="Error: Signature is invalid.")
        messagebox.showerror("Error", f"Signature is invalid: {str(e)}")
    except Exception as e:
        messagebox.showerror("Error", f"An unexpected error occurred: {str(e)}")


# Sign a file
def sign_file():
    global signature_file

    try:
        file_path = filedialog.askopenfilename(initialdir=save_dir, title="Select File to Sign")
        if not file_path:
            return

        with open(file_path, "rb") as file:
            file_data = file.read()

        hash_obj = SHA3_256.new(file_data)  # Create a SHA3_256 hash of the file data
        private_key_obj = RSA.import_key(private_key)  # Import the private key

        signature_file = pkcs1_15.new(private_key_obj).sign(hash_obj)  # Sign the hash with the private key

        status_label.config(text="File signed and signature saved.")
        messagebox.showinfo("Success", "File signed and signature saved.")
        enable_buttons([select_file_to_verify_button])
    except Exception as e:
        messagebox.showerror("Error", f"Failed to sign file: {str(e)}")


# Select file to verify
def select_file_to_verify():
    global file_to_verify_path

    try:
        file_to_verify_path = filedialog.askopenfilename(initialdir=save_dir, title="Select File to Verify")
        if file_to_verify_path:
            status_label.config(text=f"Selected file to verify: {os.path.basename(file_to_verify_path)}")
            messagebox.showinfo("Success", f"Selected file to verify: {os.path.basename(file_to_verify_path)}")
            enable_buttons([select_key_button])
    except Exception as e:
        messagebox.showerror("Error", f"Failed to select file to verify: {str(e)}")


# Select public key file
def select_key():
    global key_path

    try:
        key_path = filedialog.askopenfilename(initialdir=save_dir, title="Select Key File")
        if key_path:
            status_label.config(text=f"Selected key file: {os.path.basename(key_path)}")
            messagebox.showinfo("Success", f"Selected key file: {os.path.basename(key_path)}")
            enable_buttons([verify_file_button])
    except Exception as e:
        messagebox.showerror("Error", f"Failed to select key file: {str(e)}")


# Verify the signature of a file
def verify_file():
    try:
        if not file_to_verify_path:
            messagebox.showerror("Error", "No file selected for verification.")
            return

        if not key_path:
            messagebox.showerror("Error", "No key file selected.")
            return

        with open(file_to_verify_path, "rb") as file:
            file_data = file.read()

        with open(key_path, "rb") as key_file:
            key_data = key_file.read()
            key_obj = RSA.import_key(key_data)  # Import the key from the file

        hash_obj = SHA3_256.new(file_data)

        pkcs1_15.new(key_obj).verify(hash_obj, signature_file)
        status_label.config(text="File signature is valid.")
        messagebox.showinfo("Success", "File signature is valid.")
    except (ValueError, TypeError) as e:
        status_label.config(text="Error: File signature is invalid.")
        messagebox.showerror("Error", f"File signature is invalid: {str(e)}")
    except Exception as e:
        messagebox.showerror("Error", f"An unexpected error occurred: {str(e)}")


# Generate TRNG bits
def generate_trng_bits():
    global random_bits, bit_index

    try:
        folder_selected = filedialog.askdirectory(title="Select Folder with Images")  # Open a dialog to select a folder
        if not folder_selected:
            status_label.config(text="Error: No folder selected.")
            messagebox.showerror("Error", "No folder selected.")
            return

        num_needed = 10000000  # Number of bits needed
        random_bits = generate_random_bits_from_images(folder_selected, num_needed)  # Generate random bits
        bit_index = 0  # Reset bit index
        status_label.config(text="Random bits generated!")
        messagebox.showinfo("Success", "Random bits generated!")
        enable_buttons([generate_keys_button])
    except Exception as e:
        messagebox.showerror("Error", f"Failed to generate TRNG bits: {str(e)}")


def enable_buttons(buttons):
    for button in buttons:
        button.config(state=tk.NORMAL)


def disable_buttons(buttons):
    for button in buttons:
        button.config(state=tk.DISABLED)


def update_interface():
    if selection.get() == 1:
        message_entry.grid(row=5, column=0, columnspan=2, pady=5, padx=5, sticky="ew")
        sign_message_button.grid(row=6, column=0, pady=5, padx=5, sticky="ew")
        verify_message_button.grid(row=6, column=1, pady=5, padx=5, sticky="ew")
        sign_file_button.grid_remove()
        select_file_to_verify_button.grid_remove()
        select_key_button.grid_remove()
        verify_file_button.grid_remove()
    elif selection.get() == 2:
        message_entry.grid_remove()
        sign_message_button.grid_remove()
        verify_message_button.grid_remove()
        sign_file_button.grid(row=5, column=0, columnspan=2, pady=5, padx=5, sticky="ew")
        select_file_to_verify_button.grid(row=6, column=0, pady=5, padx=5, sticky="ew")
        select_key_button.grid(row=6, column=1, pady=5, padx=5, sticky="ew")
        verify_file_button.grid(row=7, column=0, columnspan=2, pady=5, padx=5, sticky="ew")


def initial_prompt():
    response = messagebox.askyesno("Key Check", "Do you already have the RSA keys generated?")
    if response:
        while True:
            key_folder = filedialog.askdirectory(title="Select Folder with RSA Keys")
            if not key_folder:
                messagebox.showerror("Error", "No folder selected. Please select the folder containing the RSA keys.")
                continue

            private_key_path = os.path.join(key_folder, "private.pem")
            public_key_path = os.path.join(key_folder, "public.pem")

            if not os.path.exists(private_key_path) or not os.path.exists(public_key_path):
                messagebox.showerror("Error",
                                     "Keys not found in the selected folder. Please select the correct folder.")
            else:
                try:
                    global private_key, public_key
                    with open(private_key_path, "rb") as priv_file:
                        private_key = priv_file.read()
                    with open(public_key_path, "rb") as pub_file:
                        public_key = pub_file.read()
                    break
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to import keys: {str(e)}")
                    continue

        selection.set(2)  # Set the radio button to "File"
        update_interface()
        enable_buttons([sign_file_button, select_file_to_verify_button, select_key_button, verify_file_button])
    else:
        enable_buttons([generate_trng_button])


# Set up the GUI
def setup_gui():
    global message_entry, generate_trng_button, generate_keys_button, sign_message_button, verify_message_button
    global sign_file_button, select_file_to_verify_button, select_key_button, verify_file_button
    global status_label, selection, file_to_verify_path, key_path, save_dir

    root = tk.Tk()
    root.title("Digital Signature")

    # Add background color
    root.configure(bg='#f0f8ff')  # Light blue background

    # Frame setup
    frame = tk.Frame(root, padx=10, pady=10, bg='#f0f8ff')  # Match the background color
    frame.pack(pady=20, padx=20)

    title_label = tk.Label(frame, text="RSA Key Generation and Signing", font=("Helvetica", 16, "bold"), bg='#f0f8ff')
    title_label.grid(row=0, column=0, columnspan=2, pady=(0, 20))

    generate_trng_button = tk.Button(frame, text="1. Generate TRNG Bits", command=generate_trng_bits,
                                     font=("Helvetica", 10), bg='#add8e6')
    generate_trng_button.grid(row=2, column=0, columnspan=2, pady=5, padx=5, sticky="ew")

    generate_keys_button = tk.Button(frame, text="2. Generate RSA Keys", command=generate_keys, font=("Helvetica", 10),
                                     bg='#add8e6')
    generate_keys_button.grid(row=3, column=0, columnspan=2, pady=5, padx=5, sticky="ew")

    selection = tk.IntVar()
    selection.set(1)
    message_radio = tk.Radiobutton(frame, text="Message", variable=selection, value=1, command=update_interface,
                                   font=("Helvetica", 10), bg='#f0f8ff')
    message_radio.grid(row=4, column=0, pady=5, padx=(0, 10), sticky="e")
    file_radio = tk.Radiobutton(frame, text="File", variable=selection, value=2, command=update_interface,
                                font=("Helvetica", 10), bg='#f0f8ff')
    file_radio.grid(row=4, column=1, pady=5, padx=(10, 0), sticky="w")

    message_entry = tk.Entry(frame, width=50, font=("Helvetica", 10))

    sign_message_button = tk.Button(frame, text="3. Sign Message", command=sign_message, font=("Helvetica", 10),
                                    bg='#add8e6')
    verify_message_button = tk.Button(frame, text="4. Verify Message", command=verify_message, font=("Helvetica", 10),
                                      bg='#add8e6')

    sign_file_button = tk.Button(frame, text="3. Sign File", command=sign_file, font=("Helvetica", 10), width=30,
                                 bg='#add8e6')
    select_file_to_verify_button = tk.Button(frame, text="4. Select File to Verify", command=select_file_to_verify,
                                             font=("Helvetica", 10), bg='#add8e6')
    select_key_button = tk.Button(frame, text="5. Select Key", command=select_key, font=("Helvetica", 10), bg='#add8e6')
    verify_file_button = tk.Button(frame, text="6. Verify File", command=verify_file, font=("Helvetica", 10),
                                   bg='#add8e6')

    status_label = tk.Label(frame, text="", fg="blue", font=("Helvetica", 10), bg='#f0f8ff')
    status_label.grid(row=8, column=0, columnspan=2, pady=10)

    # Disable buttons initially
    disable_buttons([generate_trng_button, generate_keys_button, sign_message_button, verify_message_button,
                     sign_file_button, select_file_to_verify_button, select_key_button, verify_file_button])

    # Ask if keys are already generated
    root.after(100, initial_prompt)

    root.mainloop()


setup_gui()
