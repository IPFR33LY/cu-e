# -*- encoding: utf-8 -*-
import datetime

# -----------------------------------------------------
# Application configurations
# ------------------------------------------------------
DEBUG = True
SECRET_KEY = 'fbf8sjJUVTTaUbxnWgVKJzbCHzIJwa8nbIPrmTWG'
PORT = 4200
HOST = 'localhost'

# -----------------------------------------------------
# SQL Alchemy configs
# -----------------------------------------------------
SQLALCHEMY_DATABASE_URI = 'sqlite:///app.db'

# -----------------------------------------------------
# ESI Configs
# -----------------------------------------------------
ESI_DATASOURCE = 'tranquility'  # Change it to 'singularity' to use the test server
ESI_SWAGGER_JSON = 'https://esi.tech.ccp.is/v1/swagger.json?datasource=%s' % ESI_DATASOURCE
ESI_SECRET_KEY = 'fbf8sjJUVTTaUbxnWgVKJzbCHzIJwa8nbIPrmTWG'  # your secret key
ESI_CLIENT_ID = 'a386f33bf4b047aea48679e7ff44cd8b'  # your client ID
ESI_CALLBACK = 'http://%s:%d/callback' % (HOST, PORT)  # the callback URI you gave CCP
ESI_USER_AGENT = 'esipy-flask-example'


# ------------------------------------------------------
# Session settings for flask login
# ------------------------------------------------------
PERMANENT_SESSION_LIFETIME = datetime.timedelta(days=30)

# ------------------------------------------------------
# DO NOT EDIT
# Fix warnings from flask-sqlalchemy / others
# ------------------------------------------------------
SQLALCHEMY_TRACK_MODIFICATIONS = True