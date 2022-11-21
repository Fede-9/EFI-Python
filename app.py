from functools import wraps
from datetime import datetime, timedelta
import hashlib
# import jwt 
from flask import Flask, jsonify, request, session, render_template
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from sqlalchemy import ForeignKey
from marshmallow import fields


# creamos la aplicacion
app = Flask(__name__)

#app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://usuario:contrasenia@host/nombreDB'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://BD2021:BD2021itec@143.198.156.171/blog'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = "acapongoloquequiero"

db = SQLAlchemy(app)

# Creamos una instancia Miigrate que recibe la app y db
migrate = Migrate(app, db)
ma = Marshmallow(app)




#MODELADO DE LA BASE

class Usuario(db.Model):
    __tablename__ = 'usuario'

    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(50), nullable=False, unique=True)
    apellido = db.Column(db.String(50), nullable=False, unique=True)
    username = db.Column(db.String(50), nullable=False, unique=True)
    email = db.Column(db.String(255), nullable=False, unique=True)
    password = db.Column(db.String(60), nullable=False, unique=True)
    estado = db.Column(db.Boolean(True), nullable=False, unique=True)
    fecha_creacion = db.Column(db.DateTime(), nullable=False, unique=True)


class Post(db.Model):
    __tablename__ = 'post'

    id = db.Column(db.Integer, primary_key=True)
    titulo = db.Column(db.String(255), nullable=False, unique=True)
    contenido_breve = db.Column(db.String(511), nullable=False, unique=True)
    contenido = db.Column(db.String(50), nullable=False, unique=True)
    fecha_creacion = db.Column(db.DateTime(), nullable=False, unique=True)
    estado = db.Column(db.Boolean(True), nullable=False, unique=True)
    usuario_id = db.Column(db.Integer(), ForeignKey("usuario.id"))
    categoria_id = db.Column(db.Integer, ForeignKey("categoria.id"))
    

    usuario = db.relationship("Usuario")
    categoria = db.relationship("Categoria")


class Categoria(db.Model):
    __tablename__ = 'categoria'

    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(255), nullable=False, unique=True)


class Rol(db.Model):
    __tablename__ = 'rol'

    id = db.Column(db.Integer, primary_key=True)
    rol_nombre = db.Column(db.String(255), nullable=False, unique=True)


class Usuario_rol(db.Model):
    __tablename__ = 'usuario_rol'

    id = db.Column(db.Integer, primary_key=True)
    usuario_id = db.Column(db.Integer(), nullable=False, unique=True)
    rol_id = db.Column(db.Integer, ForeignKey("rol.id"))

    rol = db.relationship("Rol")



# ---------- SCHEMAS ------------

class UsuarioSchema(ma.Schema):
    id = fields.Integer(dump_only=True)
    nombre = fields.String()
    apellido = fields.String()
    username = fields.String()
    email = fields.String()
    # nunca mostrar la contraseña
    # password = fields.String()
    estado = fields.Boolean()
    fecha_creacion = fields.DateTime()


class PostSchema(ma.Schema):
    id = fields.Integer(dump_only=True)
    titulo = fields.String()
    contenido_breve = fields.String()
    contenido = fields.String()
    fecha_creacion = fields.DateTime()
    estado = fields.Boolean()
    usuario_id = fields.Integer()
    categoria_id = fields.Integer()


class CategoriaSchema(ma.Schema):
    id = fields.Integer(dump_only=True)
    nombre = fields.String()


class RolSchema(ma.Schema):
    id = fields.Integer(dump_only=True)
    rol_nombre = fields.String()


class UsuarioRolSchema(ma.Schema):
    id = fields.Integer(dump_only=True)
    usuario_id = fields.Integer()
    rol_id = fields.Integer()




# ---------- RUTAS -------------

@app.route('/usuarios')
def get_usuario():
    usuario = db.session.query(Usuario).all()
    usuario_schema = UsuarioSchema().dump(usuario, many=True)
    return jsonify(usuario_schema)



# @app.route('/login')
# def login():
#     return render_template(
#         "login.html"
#     )


# @app.route('/paises')
# def get_paises():
#     pais = db.session.query(Pais).all()
#     pais_schema = PaisSerializer().dump(pais, many=True)
#     return jsonify(pais_schema)

# # aca usamos el post
# @app.route('/paises', methods=['POST'])
# def add_paises():
#     if request.method == 'POST':
#         data = request.json
#         nombre = data['nombre']
#         paises = db.session.query(Pais).all()
#         for pais in paises:
#             if nombre == pais.nombre:
#                 return jsonify({'Mensaje':'Ya existe un pais con ese nombre'}),400
#             nuevo_pais = Pais(nombre = nombre)
#             db.session.add(nuevo_pais)
#             db.session.commit()
#             pais_schema = PaisSinIdSerializer().dump(nuevo_pais)
#         return jsonify(
#             {"Mensaje": "El pais se creo correctamente"},
#             {"Pais": pais_schema}
#         ), 201
    

# @app.route('/nombre_paises')
# def get_nombre_paises():
#     pais_schema = PaisSinIdSerializer().dump(
#         db.session.query(Pais).all(), many=True
#     )
#     return jsonify(pais_schema)
    


# @app.route('/personas')
# def persona():
# # ------------- PAGINADO ------------
# # El paginado recibe 2 parametros principales: PAGINA (pag) Y CANTIDAD (can)
# # Y un tercer parametro obligatorio que es el error_out que se puede setear como vacio

#     try:
#         can = int(request.args.get('can'))
#         pag = int(request.args.get('pag'))
#         persona = Persona.query.paginate(pag, can, error_out='No se obtienen valores').items
#     except:
#         persona = db.session.query(Persona).all()
#         pag = 1
#         can = 'Todos'


#     persona_schema = PersonaSerializer().dump(persona, many=True)
#     return jsonify(dict(
#         pagina = pag,
#         cantidad = can,
#         resultado = persona_schema,
#         )
#     )
   


# @app.route('/localidades')
# def localidad():
#     localidad = db.session.query(Localidad).all()
#     localidad_schema = LocalidadSerializer().dump(localidad, many=True)
#     return jsonify(localidad_schema)


# @app.route('/sexos')
# def sexo():
#     sexo = db.session.query(Sexo).all()
#     sexo_schema = SexoSerializer().dump(sexo, many=True)
#     return jsonify(sexo_schema)


# @app.route('/tipos_dni')
# def tipoDni():
#     tipodni = db.session.query(Tipodni).all()
#     tipodni_schema = TipoDniSerializer().dump(tipodni, many=True)
#     return jsonify(tipodni_schema)


# @app.route('/usuarios')
# def get_usuario():
#     usuario = db.session.query(Usuario).all()
#     if len(usuario) == 0:
#         return jsonify(dict(Mensaje = "No existen Usuarios")), 400
#     usuario_schema = UsuarioSerializer().dump(usuario, many=True)
#     return jsonify(dict(Usuarios = usuario_schema )), 200


# @app.route('/usuarios', methods=['POST'])
# def add_usuario():
#     if request.method == 'POST':
#         data = request.json
#         print('ENTRA AL PPOST')
#         nombre = data['nombre']
#         contrasenia = data['contrasenia'].encode('utf-8')
#         idTipousuario = data['idTipousuario']
#         # fechaCarga = data['fechaCarga']
#         idPersona = data['idPersona']

#         contra_hash = hashlib.md5(contrasenia).hexdigest()

#         try:
#             nuevo_usuario = Usuario(
#                 nombre=nombre, 
#                 contrasenia=contra_hash, 
#                 idTipousuario=idTipousuario, 
#                 fechaCarga=datetime.now(), 
#                 idPersona=idPersona
#             )
#             db.session.add(nuevo_usuario)
#             db.session.commit()

#             resultado = UsuarioSerializer().dump(nuevo_usuario)

#             if resultado:
#                 return jsonify(dict(NuevoUsuario=resultado))

#         except:
#             return jsonify(dict(Error = 'No es posible generar el usuario')), 201
            


# @app.route('/login', methods=['GET'])
# def login():
#     auth = request.authorization
#     username = auth['username']
#     password = auth['password'].encode('utf-8')



#     if not auth or not auth.username or not auth.password:
#         return jsonify({"Error":"No se enviaron todos los parametros auth"}, 401)

#     hasheada = hashlib.md5(password).hexdigest()

#     user_login = db.session.query(Usuario).filter_by(nombre=username).filter_by(contrasenia=hasheada).first()
    

#     if user_login:
#         token = jwt.encode(
#             {
#                 "usuario": username, 
#                 "id_usuario": user_login.id,
#                 "exp": datetime.utcnow() + timedelta(minutes=5)
#             },
#             app.secret_key
#         )
#         session['api_session_token'] = token
   
#         return jsonify({"Token": token.decode("UTF-8")})
    
#     return jsonify({"Error":"Algun dato no coincide"}, 401)


# # ------- TOKEN ------
# def token_required(f):
#     @wraps(f)
#     def decorated(*args, **kwargs):
#         token = None
#         if 'x-access-token' in request.headers:
#             token = request.headers['x-access-token']

#         if not token:
#             return jsonify({"ERROR":"Token is missing"}),401

#         try: 
#             datatoken = jwt.decode(token, app.secret_key)
#             print(datatoken)
#             userLogged = Usuario.query.filter_by(id=datatoken['id_usuario']).first()
#         except:
#             return jsonify(
#                 {"ERROR": "Token is invalid or expired"}
#             ),401

#         return f(userLogged, *args, **kwargs)

#     return decorated


# @app.route('/provincias')
# @token_required
# def get_provincias(userLogged):
#     if userLogged.idTipousuario == 2:
#         provincia = db.session.query(Provincia).all()
#         provincia_schema = ProvinciaSerializer().dump(provincia, many=True)
#         return jsonify(provincia_schema)
#     else:
#         return jsonify({"Error":"Usted no tiene permiso!!"})


# @app.route('/provincias', methods=['POST'])
# def add_provincia():
#     if request.method == 'POST':
#         data = request.json
#         nombre = data['nombre']
#         idPais = data['idPais']
#         try:
#             nueva_provincia = Provincia(idPais=idPais, nombre=nombre)
#             db.session.add(nueva_provincia)
#             db.session.commit()

#             provincia_schema = ProvinciaSerializer().dump(nueva_provincia)

#             return jsonify(
#                 {"Mensaje": "La provincia se creo correctamente"},
#                 {"Pais": provincia_schema}
#             ), 201

#         except:
#             return jsonify(
#                 {"Mensaje": "Algo salio mal, valide los datos"},
#             ), 404


# @app.route('/tipos_usuario')
# def tipoUsuario():
#     tipousuario = db.session.query(Tipousuario).all()
#     tipousuario_schema = TipoUsuarioSerializer().dump(tipousuario, many=True)
#     return jsonify(tipousuario_schema)





if __name__ == '__main__':
    app.run(debug=True)
