# bibliotecas para cifrado simétrico:
import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# biblioteca para que el usuario introduzca contraseñas
# import getpass

def ocultar_usuario_clave(usuario, clave):
    """Esta funcion hace más seguro guardar las contraseñas en un archivo de texto,
    las claves y usuarios no son fáciles de descifrar.
    El precio que se paga es no validar si existen usuarios duplicados, su validación
    se vuelve más complicada.
    """
    partir_usuario = len(usuario) // 2 # palabras a tomar al dividir usuario
    partir_clave = len(clave) // 2     # palabras a tomar al dividir clave
    texto = usuario[:partir_usuario] + clave[:partir_clave] + usuario[partir_usuario:] + clave[partir_clave:] + '\n'
    return texto

def agregar_usuario(usuario, clave):
    texto = ocultar_usuario_clave(usuario, clave)
    with open('claves', 'a+') as archivo:
        archivo.write(texto)
        
def verificar_usuario(usuario, clave):
    texto = ocultar_usuario_clave(usuario, clave)

    with open('claves', 'r') as archivo:
        registros = archivo.readlines()

    for registro in registros:
        if registro == texto:
            return True

    return False

def clave_Fernet(clave):
    # código tomado de la documentación de la librería https://cryptography.io/en/latest/fernet/#using-passwords-with-fernet
    """El archivo se cifra usando la contraseña del usuario, por lo tanto,
    si hay usuarios que comparten una misma contraseña, entre ellos podrán
    descrifrar todos sus archivos"""
    salt = os.urandom(0)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=3900, #390000
    )
    key = base64.urlsafe_b64encode(kdf.derive(bytes(clave, 'utf-8')))
    return Fernet(key)

def cifrar_archivo(archivo_original, clave):
    f = clave_Fernet(clave)

    with open(archivo_original, 'r') as original:
         contenido = original.read()

    contenido_cifrado = f.encrypt(bytes(contenido, 'utf-8'))

    with open (archivo_original + '.cifrado', 'wb') as cifrado:
         cifrado.write(contenido_cifrado)

def descifrar_archivo(archivo, clave):
    f = clave_Fernet(clave)

    with open(archivo, 'rb') as cifrado: # debe leerse como bytes para poder descifrarse con Fernet
         contenido = cifrado.read()

    try:
        contenido_descifrado = f.decrypt(contenido)
        print(contenido_descifrado)
        return('Descrifrar exitoso.')
    except:
        print('No tienes permisos para descifrar este archivo.')
        return('Descrifrar FALLIDO.')



if __name__ == '__main__':
    lista_de_logs = [] # de este modo se escribe únicamente una vez al archivo
    usuario = input('Introduce tu usuario: ')
    clave = input('Introduce tu clave: ')

    opcion = input('1. Registrarme \n2. Identificarme\n3. Salir\n')
    if opcion == '1':
        agregar_usuario(usuario, clave)
        lista_de_logs.append('Nuevo usuario registrado: ' + usuario)
    elif opcion == '2':
        if verificar_usuario(usuario, clave):
            lista_de_logs.append('Usuario identificado:' + usuario)
            nombre_de_archivo = input('Archivo: ')
            opcion = input('1. Cifrar\n2. Descifrar\n')
            if opcion == '1':
                cifrar_archivo(nombre_de_archivo, clave)
                lista_de_logs.append('Archivo cifrado: ' + nombre_de_archivo + ' por usuario: ' + usuario)
            elif opcion == '2':
                lista_de_logs.append(descifrar_archivo(nombre_de_archivo, clave) + ' Usuario: ' + usuario)

        else:
            lista_de_logs.append('Usuario no identificado: ' + usuario)
    with open('logs', 'a+') as archivo_de_logs:
        for log in lista_de_logs:
            archivo_de_logs.write(log + '\n')

    
