# Import encryption and decryption functions from your AES tool module
from aes import encrypt, decrypt

# Main function to present user with encryption/decryption ask
def main():
    print("\n🔐 AES-256 File Encryption Tool")
    print("1. Encrypt a file")
    print("2. Decrypt a file")
    ask = input("Choose an option (1/2): ")  # Ask user for ask

    # Ask user for the file path and password
    file_path = input("Enter file path: ")
    password = input("Enter password: ")

    # Based on user ask, call the appropriate function
    if ask == '1':
        encrypt(file_path, password)  # Call function to encrypt file
    elif ask == '2':
        decrypt(file_path, password)  # Call function to decrypt file
    else:
        print("❌ Invalid option.")         # Handle invalid input

# Run the main function when script is executed directly
if __name__ == "__main__":
    main()
