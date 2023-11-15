from Crypto.Cipher import DES, DES3, AES
from secrets import token_bytes
from flask import Flask, render_template, request

app = Flask(__name__)
generator = 421
prime_modulus = 601
###################
des_key = token_bytes(8)
des3_key = token_bytes(24)
aes_key = token_bytes(16)
iv = token_bytes(8)

file_path = "Laboratorio5/mensajeentrada.txt"
with open(file_path, "r") as file:
    input_message = str(file.readline().lower()).encode()
def des_encrypt(text, key, initialization_vector):
    cipher = DES.new(key, DES.MODE_CFB, initialization_vector)
    encrypted_message = cipher.encrypt(text)
    return encrypted_message
def des_decrypt(text, key, initialization_vector):
    cipher = DES.new(key, DES.MODE_CFB, initialization_vector)
    decrypted_message = cipher.decrypt(text).decode()
    return decrypted_message
def des3_encrypt(text, key, initialization_vector):
    cipher = DES3.new(key, DES3.MODE_CFB, initialization_vector)
    encrypted_message = cipher.encrypt(text)
    return encrypted_message
def des3_decrypt(text, key, initialization_vector):
    cipher = DES3.new(key, DES3.MODE_CFB, initialization_vector)
    decrypted_message = cipher.decrypt(text).decode()
    return decrypted_message
def aes_encrypt(message):
    cipher = AES.new(aes_key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(message)
    return nonce, ciphertext, tag
def aes_decrypt(nonce, ciphertext, tag):
    cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
    decrypted_text = cipher.decrypt(ciphertext)
    try:
        cipher.verify(tag)
        return decrypted_text
    except Exception as e:
        return "Mensaje alterado"
# Cifrar el mensaje con DES
des_ciphertext = des_encrypt(input_message, des_key, iv)
print(f"\nMensaje Cifrado con DES: {des_ciphertext}")
# Desencriptar
des_decrypted_message = des_decrypt(des_ciphertext, des_key, iv)
# Guardar
with open("Laboratorio5/mensajerecibido_des.txt", "w+") as file:
    file.write(str(des_decrypted_message))

# Cifrar el mensaje con 3DES
des3_ciphertext = des3_encrypt(input_message, des3_key, iv)
print(f"\nMensaje Cifrado con 3DES: {des3_ciphertext}")
# Desencriptar
des3_decrypted_message = des3_decrypt(des3_ciphertext, des3_key, iv)
with open("Laboratorio5/mensajerecibido_3des.txt", "w+") as file:
    file.write(str(des3_decrypted_message))

# Cifrar el mensaje con AES
aes_ciphertext = aes_encrypt(input_message)
print(f"\nMensaje Cifrado con AES: {aes_ciphertext}")
# Desencriptar
aes_decrypted_message = aes_decrypt(*aes_ciphertext)
with open("Laboratorio5/mensajerecibido_aes.txt", "w+") as file:
    file.write(str(aes_decrypted_message))

#DES
if input_message == des_decrypted_message.encode():
    print("\nVerificación DES: El mensaje original coincide con el mensaje desencriptado con DES.")
else:
    print("\nVerificación DES: El mensaje original no coincide con el mensaje desencriptado con DES.")
#3DES
if input_message == des3_decrypted_message.encode():
    print("Verificación 3DES: El mensaje original coincide con el mensaje desencriptado con 3DES.")
else:
    print("Verificación 3DES: El mensaje original no coincide con el mensaje desencriptado con 3DES.")

#AES
if input_message == aes_decrypted_message:
    print("Verificación AES: El mensaje original coincide con el mensaje desencriptado con AES.")
else:
    print("Verificación AES: El mensaje original no coincide con el mensaje desencriptado con AES.")
