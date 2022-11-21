"""Initial migration.

Revision ID: b45f5afa34dd
Revises: 
Create Date: 2022-11-21 13:47:41.564617

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision = 'b45f5afa34dd'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.alter_column('categoria', 'id',
               existing_type=mysql.INTEGER(display_width=10),
               comment=None,
               existing_comment='llave primaria',
               existing_nullable=False,
               autoincrement=True)
    op.alter_column('categoria', 'nombre',
               existing_type=mysql.VARCHAR(length=255),
               comment=None,
               existing_comment='nombre de la categoria',
               existing_nullable=False)
    op.create_unique_constraint(None, 'categoria', ['nombre'])
    op.alter_column('post', 'id',
               existing_type=mysql.INTEGER(display_width=10),
               comment=None,
               existing_comment='llave primaria',
               existing_nullable=False,
               autoincrement=True)
    op.alter_column('post', 'titulo',
               existing_type=mysql.VARCHAR(length=255),
               comment=None,
               existing_comment='titulo del articulo',
               existing_nullable=False)
    op.alter_column('post', 'contenido_breve',
               existing_type=mysql.VARCHAR(length=511),
               comment=None,
               existing_comment='contenido corto del articulo',
               existing_nullable=False)
    op.alter_column('post', 'contenido',
               existing_type=mysql.TEXT(),
               comment=None,
               existing_comment='contenido completo del articulo',
               existing_nullable=False)
    op.alter_column('post', 'fecha_creacion',
               existing_type=mysql.DATETIME(),
               comment=None,
               existing_comment='fecha de creación del articulo',
               existing_nullable=False)
    op.alter_column('post', 'estado',
               existing_type=mysql.TINYINT(display_width=1),
               comment=None,
               existing_comment='0 = inactivo - 1 = activo',
               existing_nullable=False,
               existing_server_default=sa.text('1'))
    op.alter_column('post', 'usuario_id',
               existing_type=mysql.INTEGER(display_width=10),
               nullable=True,
               comment=None,
               existing_comment='id del usuario que escribe el articulo')
    op.alter_column('post', 'categoria_id',
               existing_type=mysql.INTEGER(display_width=10),
               nullable=True,
               comment=None,
               existing_comment='id de la categoría a la que pertenece el articulo')
    op.create_unique_constraint(None, 'post', ['contenido'])
    op.create_unique_constraint(None, 'post', ['fecha_creacion'])
    op.create_unique_constraint(None, 'post', ['estado'])
    op.create_unique_constraint(None, 'post', ['contenido_breve'])
    op.create_unique_constraint(None, 'post', ['titulo'])
    op.alter_column('rol', 'id',
               existing_type=mysql.INTEGER(display_width=10),
               comment=None,
               existing_comment='llave primaria',
               existing_nullable=False,
               autoincrement=True)
    op.alter_column('rol', 'rol_nombre',
               existing_type=mysql.VARCHAR(length=255),
               comment=None,
               existing_comment='nombre del rol',
               existing_nullable=False)
    op.create_unique_constraint(None, 'rol', ['rol_nombre'])
    op.alter_column('usuario', 'id',
               existing_type=mysql.INTEGER(display_width=10),
               comment=None,
               existing_comment='llave primaria',
               existing_nullable=False,
               autoincrement=True)
    op.alter_column('usuario', 'nombre',
               existing_type=mysql.VARCHAR(length=50),
               comment=None,
               existing_comment='nombre del usuario',
               existing_nullable=False)
    op.alter_column('usuario', 'apellido',
               existing_type=mysql.VARCHAR(length=50),
               comment=None,
               existing_comment='apellido del usuario',
               existing_nullable=False)
    op.alter_column('usuario', 'username',
               existing_type=mysql.VARCHAR(length=50),
               comment=None,
               existing_comment='nombre de usuario o identificador',
               existing_nullable=False)
    op.alter_column('usuario', 'email',
               existing_type=mysql.VARCHAR(length=255),
               comment=None,
               existing_comment='direccion de correo electronico del usuario',
               existing_nullable=False)
    op.alter_column('usuario', 'password',
               existing_type=mysql.VARCHAR(length=60),
               comment=None,
               existing_comment='contraseña del usuario',
               existing_nullable=False)
    op.alter_column('usuario', 'estado',
               existing_type=mysql.TINYINT(display_width=1),
               comment=None,
               existing_comment='0 = inactivo - 1 = activo',
               existing_nullable=False,
               existing_server_default=sa.text('1'))
    op.alter_column('usuario', 'fecha_creacion',
               existing_type=mysql.TIMESTAMP(),
               comment=None,
               existing_comment='fecha de creación del usuario',
               existing_nullable=False,
               existing_server_default=sa.text('current_timestamp() ON UPDATE current_timestamp()'))
    op.create_unique_constraint(None, 'usuario', ['username'])
    op.create_unique_constraint(None, 'usuario', ['email'])
    op.create_unique_constraint(None, 'usuario', ['password'])
    op.create_unique_constraint(None, 'usuario', ['estado'])
    op.create_unique_constraint(None, 'usuario', ['fecha_creacion'])
    op.create_unique_constraint(None, 'usuario', ['nombre'])
    op.create_unique_constraint(None, 'usuario', ['apellido'])
    op.alter_column('usuario_rol', 'id',
               existing_type=mysql.INTEGER(display_width=10),
               comment=None,
               existing_comment='llave primaria',
               existing_nullable=False,
               autoincrement=True)
    op.alter_column('usuario_rol', 'usuario_id',
               existing_type=mysql.INTEGER(display_width=10),
               comment=None,
               existing_comment='id del usuario',
               existing_nullable=False)
    op.alter_column('usuario_rol', 'rol_id',
               existing_type=mysql.INTEGER(display_width=10),
               nullable=True,
               comment=None,
               existing_comment='id del rol del usuario')
    op.create_unique_constraint(None, 'usuario_rol', ['usuario_id'])
    op.drop_constraint('usuario_rol_ibfk_1', 'usuario_rol', type_='foreignkey')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_foreign_key('usuario_rol_ibfk_1', 'usuario_rol', 'usuario', ['usuario_id'], ['id'])
    op.drop_constraint(None, 'usuario_rol', type_='unique')
    op.alter_column('usuario_rol', 'rol_id',
               existing_type=mysql.INTEGER(display_width=10),
               nullable=False,
               comment='id del rol del usuario')
    op.alter_column('usuario_rol', 'usuario_id',
               existing_type=mysql.INTEGER(display_width=10),
               comment='id del usuario',
               existing_nullable=False)
    op.alter_column('usuario_rol', 'id',
               existing_type=mysql.INTEGER(display_width=10),
               comment='llave primaria',
               existing_nullable=False,
               autoincrement=True)
    op.drop_constraint(None, 'usuario', type_='unique')
    op.drop_constraint(None, 'usuario', type_='unique')
    op.drop_constraint(None, 'usuario', type_='unique')
    op.drop_constraint(None, 'usuario', type_='unique')
    op.drop_constraint(None, 'usuario', type_='unique')
    op.drop_constraint(None, 'usuario', type_='unique')
    op.drop_constraint(None, 'usuario', type_='unique')
    op.alter_column('usuario', 'fecha_creacion',
               existing_type=mysql.TIMESTAMP(),
               comment='fecha de creación del usuario',
               existing_nullable=False,
               existing_server_default=sa.text('current_timestamp() ON UPDATE current_timestamp()'))
    op.alter_column('usuario', 'estado',
               existing_type=mysql.TINYINT(display_width=1),
               comment='0 = inactivo - 1 = activo',
               existing_nullable=False,
               existing_server_default=sa.text('1'))
    op.alter_column('usuario', 'password',
               existing_type=mysql.VARCHAR(length=60),
               comment='contraseña del usuario',
               existing_nullable=False)
    op.alter_column('usuario', 'email',
               existing_type=mysql.VARCHAR(length=255),
               comment='direccion de correo electronico del usuario',
               existing_nullable=False)
    op.alter_column('usuario', 'username',
               existing_type=mysql.VARCHAR(length=50),
               comment='nombre de usuario o identificador',
               existing_nullable=False)
    op.alter_column('usuario', 'apellido',
               existing_type=mysql.VARCHAR(length=50),
               comment='apellido del usuario',
               existing_nullable=False)
    op.alter_column('usuario', 'nombre',
               existing_type=mysql.VARCHAR(length=50),
               comment='nombre del usuario',
               existing_nullable=False)
    op.alter_column('usuario', 'id',
               existing_type=mysql.INTEGER(display_width=10),
               comment='llave primaria',
               existing_nullable=False,
               autoincrement=True)
    op.drop_constraint(None, 'rol', type_='unique')
    op.alter_column('rol', 'rol_nombre',
               existing_type=mysql.VARCHAR(length=255),
               comment='nombre del rol',
               existing_nullable=False)
    op.alter_column('rol', 'id',
               existing_type=mysql.INTEGER(display_width=10),
               comment='llave primaria',
               existing_nullable=False,
               autoincrement=True)
    op.drop_constraint(None, 'post', type_='unique')
    op.drop_constraint(None, 'post', type_='unique')
    op.drop_constraint(None, 'post', type_='unique')
    op.drop_constraint(None, 'post', type_='unique')
    op.drop_constraint(None, 'post', type_='unique')
    op.alter_column('post', 'categoria_id',
               existing_type=mysql.INTEGER(display_width=10),
               nullable=False,
               comment='id de la categoría a la que pertenece el articulo')
    op.alter_column('post', 'usuario_id',
               existing_type=mysql.INTEGER(display_width=10),
               nullable=False,
               comment='id del usuario que escribe el articulo')
    op.alter_column('post', 'estado',
               existing_type=mysql.TINYINT(display_width=1),
               comment='0 = inactivo - 1 = activo',
               existing_nullable=False,
               existing_server_default=sa.text('1'))
    op.alter_column('post', 'fecha_creacion',
               existing_type=mysql.DATETIME(),
               comment='fecha de creación del articulo',
               existing_nullable=False)
    op.alter_column('post', 'contenido',
               existing_type=mysql.TEXT(),
               comment='contenido completo del articulo',
               existing_nullable=False)
    op.alter_column('post', 'contenido_breve',
               existing_type=mysql.VARCHAR(length=511),
               comment='contenido corto del articulo',
               existing_nullable=False)
    op.alter_column('post', 'titulo',
               existing_type=mysql.VARCHAR(length=255),
               comment='titulo del articulo',
               existing_nullable=False)
    op.alter_column('post', 'id',
               existing_type=mysql.INTEGER(display_width=10),
               comment='llave primaria',
               existing_nullable=False,
               autoincrement=True)
    op.drop_constraint(None, 'categoria', type_='unique')
    op.alter_column('categoria', 'nombre',
               existing_type=mysql.VARCHAR(length=255),
               comment='nombre de la categoria',
               existing_nullable=False)
    op.alter_column('categoria', 'id',
               existing_type=mysql.INTEGER(display_width=10),
               comment='llave primaria',
               existing_nullable=False,
               autoincrement=True)
    # ### end Alembic commands ###