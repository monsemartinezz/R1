# Importa las clases y funciones necesarias de los módulos
from flask import Flask, jsonify, request  # Importa Flask para crear la aplicación web y manejar solicitudes HTTP
import re  # Importa el módulo 're' para realizar operaciones de expresiones regulares
import bcrypt  # Importa bcrypt para el hashing de contraseñas
import mysql.connector  # Importa el conector MySQL para interactuar con la base de datos
from datetime import datetime  # Importa la clase 'datetime' para trabajar con fechas y horas

# Crea una instancia de la aplicación Flask
app = Flask(__name__)

# Lista de usuarios (simulación, no se utiliza en el código actual)
usuarios = [
    {'username':'user1', 'email':'user1@gmail.com', 'password':''},
    {'username':'user2', 'email':'user2@gmail.com', 'password':''},
    {'username':'user3', 'email':'user3mail.com', 'password':''},
    {'username':'user4', 'email':'user4@gmail.com', 'password':''},
    {'username':'user5', 'email':'user5@gmail.com', 'password':''},
]

# Configuración de la conexión a la base de datos MySQL
conexion = {
    'user': 'root',
    'password': '041022',
    'host': '172.30.32.1',
    'database': 'Recuperacion_db'
}

# Establece una conexión a la base de datos MySQL y crea un cursor para consultas
conn = mysql.connector.connect(**conexion)
cursor = conn.cursor(dictionary=True)

# Función para validar si una contraseña cumple con ciertos criterios
def is_valid_password(password):
    if len(password) < 8 or len(password) > 15:
        return False
    if not re.search(r'[A-Z]', password):
        return False
    if not re.search(r'[a-z]', password):
        return False
    if not re.search(r'[!\"#$%&/()]', password):
        return False
    return True

# Función para validar si una fecha de expiración es válida
def is_valid_expiration_date(expiration_date):
    try:
        expiration_date = datetime.strptime(expiration_date, '%Y-%m-%d')
        current_date = datetime.now()
        return expiration_date >= current_date
    except ValueError:
        return False

# Ruta para obtener información de usuarios mediante una solicitud GET
@app.route('/usuarios', methods=['GET'])
def get_usuarios():
    try:
        conn = mysql.connector.connect(**conexion)  # Se establece una nueva conexión
        cursor = conn.cursor(dictionary=True)  # Se crea un cursor

        query = "SELECT username, email FROM usuarios"  # Consulta SQL para seleccionar usuarios
        cursor.execute(query)  # Se ejecuta la consulta
        usuarios = cursor.fetchall()  # Se obtienen los resultados de la consulta

        return jsonify(usuarios), 200  # Se devuelve la lista de usuarios en formato JSON
    finally:
        cursor.close()  # Se cierra el cursor
        conn.close()  # Se cierra la conexión


#@app.get('/usuarios')
#def get_usuarios():
#    return jsonify(usuarios),200

#--------------------------ADMINISTRADOR------------------------------------------

# Define una ruta para agregar usuarios mediante una solicitud POST
@app.post('/usuarios')
def add_usuarios():
    datos = request.get_json()  # Obtiene los datos JSON de la solicitud
    if 'password' in datos:  # Verifica si la clave 'password' está en los datos
        password = datos['password']

        # Realiza una serie de validaciones en la contraseña
        if (len(password) < 8 or len(password) > 15 or
            not re.search(r'[A-Z]', password) or
            not re.search(r'[a-z]', password) or
            not re.search(r'[!\"#$%&/()]', password) or
            not re.search(r'\d', password)):
            return {'error': 'Formato de contraseña inválido'}, 400

        expiration_date = datos.get('expiration_date')  # Obtiene la fecha de expiración de los datos (si existe)
        if expiration_date:
            try:
                expiration_date = datetime.strptime(expiration_date, '%Y-%m-%d')
            except ValueError:
                return {'error': 'Fecha de expiración inválida'}, 400
        
        # Realiza el hash de la contraseña y actualiza los datos con el hash
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        datos['password'] = hashed_password.decode('utf-8')

        # Consulta SQL para agregar un usuario a la base de datos
        add_usuarios = ("INSERT INTO usuarios "
                              "(username, email, password, expiration_date) "
                              "VALUES (%s, %s, %s, %s)")

        # Ejecuta la consulta SQL y guarda los cambios en la base de datos
        cursor.execute(add_usuarios, (datos['username'], datos['email'], datos['password'], expiration_date))
        conn.commit()
        cursor.close()  # Cierra el cursor
        return {'success': 'Registro agregado con éxito'}, 201  # Retorna una respuesta exitosa
    else:
        return {'error': 'Es requerida la contraseña'}, 400  # Retorna un error si la contraseña no está presente en los datos

# Define una ruta para actualizar usuarios mediante una solicitud PUT
@app.put('/usuarios/<int:user_id>')
def update_usuario(user_id):
    datos = request.get_json()  # Obtiene los datos JSON de la solicitud
    if 'password' in datos:  # Verifica si la clave 'password' está en los datos
        password = datos['password']

        # Realiza validaciones en la contraseña y la fecha de expiración (si existe)
        if (not is_valid_password(password) or
            not re.search(r'\d', password)):
            return {'error': 'Formato de contraseña inválido'}, 400
        
        expiration_date = datos.get('expiration_date')
        if expiration_date and not is_valid_expiration_date(expiration_date):
            return {'error': 'Fecha de expiración inválida'}, 400
        
        # Establece una nueva conexión a la base de datos y crea un cursor
        try:
            conn = mysql.connector.connect(**conexion)
            cursor = conn.cursor(dictionary=True)

            # Verifica si el nombre de usuario y el correo electrónico ya existen (excepto el usuario actual)
            cursor.execute("SELECT * FROM usuarios WHERE username = %s AND id != %s", (datos['username'], user_id))
            existing_username = cursor.fetchone()
            if existing_username:
                return {'error': 'Nombre de usuario ya existe'}, 400

            cursor.execute("SELECT * FROM usuarios WHERE email = %s AND id != %s", (datos['email'], user_id))
            existing_email = cursor.fetchone()
            if existing_email:
                return {'error': 'Correo electrónico ya existe'}, 400

            # Realiza el hash de la contraseña y actualiza los datos con el hash
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            datos['password'] = hashed_password.decode('utf-8')

            # Consulta SQL para actualizar un usuario en la base de datos
            update_usuarios = ("UPDATE usuarios "
                                 "SET username = %s, email = %s, password = %s, expiration_date = %s "
                                 "WHERE id = %s")

            # Ejecuta la consulta SQL y guarda los cambios en la base de datos
            cursor.execute(update_usuarios, (datos['username'], datos['email'], datos['password'], expiration_date, user_id))
            conn.commit()

            return {'success': 'Registro actualizado con éxito'}, 200  # Retorna una respuesta exitosa
        finally:
            cursor.close()  # Cierra el cursor
            conn.close()    # Cierra la conexión a la base de datos
    else:
        return {'error': 'Es requerida la contraseña'}, 400  # Retorna un error si la contraseña no está presente en los datos

# Define una ruta para eliminar usuarios mediante una solicitud DELETE
@app.delete('/usuarios/<int:user_id>')
def delete_usuario(user_id):
    try:
        conn = mysql.connector.connect(**conexion)  # Establece una nueva conexión
        cursor = conn.cursor(dictionary=True)  # Crea un cursor

        # Consulta SQL para eliminar un usuario de la base de datos
        delete_usuarios = "DELETE FROM usuarios WHERE id = %s"
        cursor.execute(delete_usuarios, (user_id,))  # Ejecuta la consulta
        conn.commit()  # Guarda los cambios en la base de datos

        return {'success': 'Registro eliminado con éxito'}, 200  # Retorna una respuesta exitosa
    finally:
        cursor.close()  # Cierra el cursor
        conn.close()    # Cierra la conexión a la base de datos

#---------------------------------LOGIN------------------------------------------------------------------------------

# Define una ruta para manejar las solicitudes relacionadas con el inicio de sesión
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':  # Verifica si la solicitud es de tipo POST
        datos = request.get_json()  # Obtiene los datos JSON de la solicitud

        # Verifica si 'email' y 'password' están presentes en los datos
        if 'email' not in datos or 'password' not in datos:
            return {'error': 'Usuario o email faltante'}, 400

        email_or_username = datos['email']  # Obtiene el valor de 'email' de los datos
        password = datos['password']  # Obtiene el valor de 'password' de los datos

        try:
            conn = mysql.connector.connect(**conexion)  # Establece una nueva conexión a la base de datos
            cursor = conn.cursor(dictionary=True)  # Crea un cursor para consultas

            # Verifica si 'email_or_username' es un correo electrónico o un nombre de usuario
            if re.match(r"[^@]+@[^@]+\.[^@]+", email_or_username):
                campo = f"SELECT * FROM usuarios WHERE email = '{email_or_username}'"
            else:
                campo = f"SELECT * FROM usuarios WHERE username = '{email_or_username}'"

            cursor.execute(campo)  # Ejecuta la consulta SQL para buscar al usuario
            user = cursor.fetchone()  # Obtiene la primera fila de resultados

            if user:
                hashed_password = user['password'].encode('utf-8')
                if bcrypt.checkpw(password.encode('utf-8'), hashed_password):
                    return {'message': 'Inicio de sesión correcto'}, 200  # Retorna un mensaje exitoso si la contraseña coincide
                else:
                    return {'error': 'Contraseña incorrecta'}, 401  # Retorna un error si la contraseña es incorrecta
            else:
                return {'error': 'Usuario no encontrado'}, 404  # Retorna un error si el usuario no existe en la base de datos
        finally:
            cursor.close()  # Cierra el cursor
            conn.close()    # Cierra la conexión a la base de datos

    else:  # Si la solicitud no es de tipo POST
        return {'message': 'Bienvenido a la página de inicio de sesión'}, 200  # Retorna un mensaje de bienvenida

#------------------------------------PRODUCTO------------------------------------------------------------------#

# Define una ruta para obtener todos los productos mediante una solicitud GET
@app.route('/productos', methods=['GET'])
def get_productos():
    try:
        conn = mysql.connector.connect(**conexion)  # Establece una nueva conexión a la base de datos
        cursor = conn.cursor(dictionary=True)  # Crea un cursor para consultas

        consulta = "SELECT * FROM productos"  # Consulta SQL para seleccionar todos los productos
        cursor.execute(consulta)  # Ejecuta la consulta
        productos = cursor.fetchall()  # Obtiene todos los productos

        return jsonify(productos), 200  # Retorna una lista de productos en formato JSON
    finally:
        cursor.close()  # Cierra el cursor
        conn.close()    # Cierra la conexión a la base de datos

# Define una ruta para agregar un producto mediante una solicitud POST
@app.route('/productos', methods=['POST'])
def add_producto():
    try:
        datos = request.get_json()  # Obtiene los datos JSON de la solicitud
        campo_obligatorio = ['nombre', 'precio_compra', 'precio_venta', 'descripcion', 'stock', 'valoracion', 'categoria']

        # Realiza validaciones en los campos obligatorios
        for campo in campo_obligatorio:
            if campo not in datos or not datos[campo]:
                return {'error': f'Campo {campo} es requerido'}, 400
            if isinstance(datos[campo], str) and len(datos[campo]) > 255:
                return {'error': f'Campo {campo} excede la longitud máxima permitida'}, 400

        add_producto = ("INSERT INTO productos "
                            "(nombre, precio_compra, precio_venta, descripcion, stock, valoracion, categoria) "
                            "VALUES (%s, %s, %s, %s, %s, %s, %s)")

        conn = mysql.connector.connect(**conexion)  # Establece una nueva conexión a la base de datos
        cursor = conn.cursor(dictionary=True)  # Crea un cursor para consultas

        cursor.execute(add_producto, (datos['nombre'], datos['precio_compra'], datos['precio_venta'],
                                      datos['descripcion'], datos['stock'], datos['valoracion'],
                                      datos['categoria']))  # Ejecuta la consulta para agregar un producto
        producto_id = cursor.lastrowid  # Obtiene el ID del producto recién agregado
        conn.commit()  # Guarda los cambios en la base de datos
        return {'success': 'Producto agregado con éxito', 'producto_id': producto_id}, 201  # Retorna una respuesta exitosa

    except Exception as e:
        conn.rollback()  # Revierte los cambios en caso de excepción
        return {'error': 'Ocurrió un error al agregar el producto', 'exception': str(e)}, 500  # Retorna un error con detalles
    finally:
        cursor.close()  # Cierra el cursor
        conn.close()    # Cierra la conexión a la base de datos

#----------------------COMENTARIO-----------------------------------------------------------------------------------------------    

# Define una ruta para obtener todos los comentarios mediante una solicitud GET
@app.route('/comentarios', methods=['GET'])
def get_comentarios():
    try:
        conn = mysql.connector.connect(**conexion)  # Establece una nueva conexión a la base de datos
        cursor = conn.cursor(dictionary=True)  # Crea un cursor para consultas

        consulta = "SELECT * FROM comentarios"  # Consulta SQL para seleccionar todos los comentarios
        cursor.execute(consulta)  # Ejecuta la consulta
        comentarios = cursor.fetchall()  # Obtiene todos los comentarios

        return jsonify(comentarios), 200  # Retorna una lista de comentarios en formato JSON
    finally:
        cursor.close()  # Cierra el cursor
        conn.close()    # Cierra la conexión a la base de datos

# Establece una conexión a la base de datos y crea un cursor para consultas
conn = mysql.connector.connect(**conexion)
cursor = conn.cursor(dictionary=True)

# Define una ruta para agregar un comentario mediante una solicitud POST
@app.route('/comentarios', methods=['POST'])
def add_comentario():
    try:
        datos = request.get_json()  # Obtiene los datos JSON de la solicitud
        campo_obligatorio = ['comentario', 'autor', 'puntuacion', 'producto_id', 'me_gusta', 'no_me_gusta']

        # Realiza validaciones en los campos obligatorios
        for campo in campo_obligatorio:
            if campo not in datos or not datos[campo]:
                return {'error': f'Campo {campo} es requerido'}, 400
            if isinstance(datos[campo], str) and len(datos[campo]) > 255:
                return {'error': f'Campo {campo} excede la longitud máxima permitida'}, 400

        add_comentario = ("INSERT INTO comentarios "
                          "(comentario, autor, puntuacion, producto_id, me_gusta, no_me_gusta, fecha) "
                          "VALUES (%s, %s, %s, %s, %s, %s, NOW())")

        conn = mysql.connector.connect(**conexion)  # Establece una nueva conexión a la base de datos
        cursor = conn.cursor(dictionary=True)  # Crea un cursor para consultas

        cursor.execute(add_comentario, (datos['comentario'], datos['autor'], datos['puntuacion'],
                                        datos['producto_id'], datos['me_gusta'], datos['no_me_gusta']))
        conn.commit()  # Guarda los cambios en la base de datos

        return {'success': 'Comentario agregado con éxito'}, 201  # Retorna una respuesta exitosa
    except Exception as e:
        conn.rollback()  # Revierte los cambios en caso de excepción
        return {'error': 'Ocurrió un error al agregar el comentario', 'exception': str(e)}, 500  # Retorna un error con detalles

    finally:
        if 'cursor' in locals():
            cursor.close()  # Cierra el cursor
        if 'conn' in locals():
            conn.close()    # Cierra la conexión a la base de datos