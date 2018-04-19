# -*- encoding: utf-8 -*-
import ast
import json
from datetime import datetime

import requests
from esipy import App
from esipy import EsiClient
from esipy import EsiSecurity
from esipy.exceptions import APIException

from flask import Flask
from flask import redirect
from flask import render_template
from flask import request
from flask import session
from flask import url_for

from flask_login import LoginManager
from flask_login import UserMixin
from flask_login import current_user
from flask_login import login_required
from flask_login import login_user
from flask_login import logout_user

from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm.exc import NoResultFound

import config
import hashlib
import hmac
import logging
import random
import time

# logger stuff
logger = logging.getLogger(__name__)
formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
console = logging.StreamHandler()
console.setLevel(logging.DEBUG)
console.setFormatter(formatter)
logger.addHandler(console)

# init app and load conf
app = Flask(__name__)
app.config.from_object(config)
cache_timer = 0
# init db
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# init flask login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


### This is a proper change - different branch

# -----------------------------------------------------------------------
# Database models
# -----------------------------------------------------------------------
class User(db.Model, UserMixin):
    # our ID is the character ID from EVE API
    character_id = db.Column(
        db.BigInteger,
        primary_key=True,
        autoincrement=False
    )
    character_owner_hash = db.Column(db.String(255))
    character_name = db.Column(db.String(200))
    character_contacts_id = db.Column(db.String(20000))

    # SSO Token stuff
    access_token = db.Column(db.String(100))
    access_token_expires = db.Column(db.DateTime())
    refresh_token = db.Column(db.String(100))

    def get_id(self):
        """ Required for flask-login """
        return self.character_id

    def get_sso_data(self):
        """ Little "helper" function to get formated data for esipy security
        """
        return {
            'access_token': self.access_token,
            'refresh_token': self.refresh_token,
            'expires_in': (
                    self.access_token_expires - datetime.utcnow()
            ).total_seconds()
        }

    def update_token(self, token_response):
        """ helper function to update token data from SSO response """
        self.access_token = token_response['access_token']
        self.access_token_expires = datetime.fromtimestamp(
            time.time() + token_response['expires_in'],
        )
        if 'refresh_token' in token_response:
            self.refresh_token = token_response['refresh_token']


class Contact(db.Model):
    character_id = db.Column(db.BigInteger, primary_key=True, autoincrement=False
                             )
    character_contact_id = db.Column(db.BigInteger)
    character_contact_standing = db.Column(db.String(100))

    def update_standing(self, character_id, standing):
        if self.character_contact_id == character_id:
            self.character_contact_standing = standing
            print("Successfully changed %d standing to %d".format(character_id, standing))


class Killmails(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    solar_system = db.Column(db.Integer)
    killmail_time = db.Column(db.String(20000, convert_unicode=True))
    attackers = db.Column(db.String(20000))
    zkb = db.Column(db.String(20000))
    victim = db.Column(db.String(20000))
    killmail_id = db.Column(db.Integer)

    def insert_killmails(self):
        pass

    def parse_killmails(self):
        pass


# -----------------------------------------------------------------------
# Flask Login requirements
# -----------------------------------------------------------------------
@login_manager.user_loader
def load_user(character_id):
    """ Required user loader for Flask-Login """
    return User.query.get(character_id)


# -----------------------------------------------------------------------
# ESIPY Init
# -----------------------------------------------------------------------
# create the app
esiapp = App.create(config.ESI_SWAGGER_JSON)

# init the security object
esisecurity = EsiSecurity(app=esiapp,redirect_uri=config.ESI_CALLBACK,client_id=config.ESI_CLIENT_ID,secret_key=config.ESI_SECRET_KEY,)

# init the client
esiclient = EsiClient(
    security=esisecurity,
    cache=None,
    headers={'User-Agent': config.ESI_USER_AGENT}
)


# -----------------------------------------------------------------------
# Login / Logout Routes
# -----------------------------------------------------------------------
def generate_token():
    """Generates a non-guessable OAuth token"""
    chars = ('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789')
    rand = random.SystemRandom()
    random_string = ''.join(rand.choice(chars) for _ in range(40))
    return hmac.new(
        config.SECRET_KEY,
        random_string,
        hashlib.sha256
    ).hexdigest()


@app.route('/sso/login')
def login():
    """ this redirects the user to the EVE SSO login """
    token = generate_token()
    session['token'] = token
    return redirect(esisecurity.get_auth_uri(
        scopes=['esi-wallet.read_character_wallet.v1 esi-characters.read_contacts.v1 esi-characters.write_contacts.v1'],
        state=token,
    ))


@app.route('/sso/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for("index"))


@app.route('/callback')
def callback():
    """ This is where the user comes after he logged in SSO """
    # get the code from the login process
    code = request.args.get('code')
    token = request.args.get('state')

    # compare the state with the saved token for CSRF check
    sess_token = session.pop('token', None)
    if sess_token is None or token is None or token != sess_token:
        return 'Login EVE Online SSO failed: Session Token Mismatch', 403

    # now we try to get tokens
    try:
        auth_response = esisecurity.auth(code)
    except APIException as e:
        return 'Login EVE Online SSO failed: %s' % e, 403

    # we get the character informations
    cdata = esisecurity.verify()

    # if the user is already authed, we log him out
    if current_user.is_authenticated:
        logout_user()

    # now we check in database, if the user exists
    # actually we'd have to also check with character_owner_hash, to be
    # sure the owner is still the same, but that's an example only...
    try:
        user = User.query.filter(
            User.character_id == cdata['CharacterID'],
        ).one()

    except NoResultFound:
        user = User()
        user.character_id = cdata['CharacterID']

    user.character_owner_hash = cdata['CharacterOwnerHash']
    user.character_name = cdata['CharacterName']
    user.update_token(auth_response)

    # now the user is ready, so update/create it and log the user
    try:
        db.session.merge(user)
        db.session.commit()

        login_user(user)
        session.permanent = True

    except:
        logger.exception("Cannot login the user - uid: %d" % user.character_id)
        db.session.rollback()
        logout_user()

    return redirect(url_for("index"))


# -----------------------------------------------------------------------
# Index Routes
# -----------------------------------------------------------------------
@app.route('/updatecontacts', methods=['POST'])
def updateContacts():
    print('Updating Contacts')
    return


@app.route('/', methods=['POST', 'GET'])
def index():
    """
    Fill this in later
    :return:
    """
    wallet = None
    ganked_kills = None
    global cache_timer
    code = False
    # if the user is authed, get the wallet content !
    if current_user.is_authenticated:
        # give the token data to esisecurity, it will check alone
        # if the access token need some update
        esisecurity.update_token(current_user.get_sso_data())

        op = esiapp.op['get_characters_character_id_wallet'](
            character_id=current_user.character_id
        )
        # op2 = esiapp.op['get_characters_character_id_contacts'](character_id=current_user.character_id)
        wallet = esiclient.request(op)
        # contact_list = esiclient.request(op2)
        # if contact_list is not None:
        #     for x in contact_list.data:
        #         if x['contact_type'] not in ('corporation', 'alliance'):
        #             op3 = esiapp.op['get_characters_names'](character_ids=str(x['contact_id']))
        #             character_name = esiclient.request(op3).data[0]['character_name']
        #             x['character_name'] = character_name

        ###############################
        ### Beging Killmail Parsing ###
        ###############################
        # Kill ID url: https://zkillboard.com/api/killID/69334556/
        # Ganked Url: https://zkillboard.com/api/ganked/
        ct = time.time()
        if (ct - cache_timer) > float(900):
            print(ct - cache_timer)
            ganked_kills = json.loads(requests.get('https://zkillboard.com/api/ganked/').content)
            km = Killmails()
            cache_timer = time.time()
            for killmail in ganked_kills:
                try:
                    km.query.filter_by(killmail_id=killmail['killmail_id']).one()
                except NoResultFound:
                    km.attackers = str(killmail['attackers'])
                    km.killmail_id = int(killmail['killmail_id'])
                    km.killmail_time = str(killmail['killmail_time'])
                    km.solar_system = int(killmail['solar_system_id'])
                    km.victim = str(killmail['victim'])
                    try:
                        db.session.merge(km)
                        db.session.commit()
                    except:
                        logger.exception("Cannot login the user - uid: %d" % km.killmail_id)
                        db.session.rollback()

        print(ct - cache_timer)
        kms = Killmails.query.all()
        t = 0
        ## CODE. Alliance ID: 99002775
        atk_list = []
        old_cid = []
        new_cids = []
        for x in range(len(kms)):
            l = len(ast.literal_eval(ast.literal_eval(json.dumps(kms[x].attackers))))
            for a in range(l):
                attks = ast.literal_eval(ast.literal_eval(json.dumps(kms[x].attackers)))[a]
                try:
                    if attks['alliance_id'] == 99002775:
                        code = True
                        pass
                except KeyError:
                    try:
                        old_cid.append(attks['character_id'])
                    except KeyError:
                        pass
        if code:
            for a in range(l):
                cid = attks['character_id']
                new_cids.append(cid)

            op5 = esiapp.op['post_characters_character_id_contacts_contact_ids'](character_id='{}'.format(cid))
            char = esiclient.request(op5)




            pass
            ast.literal_eval(ast.literal_eval(json.dumps(kms[x].attackers)))[x]['character_id']

            pass



        # op5 = esiapp.op['get_characters_character_id_ok'](character_id='{}'.format(cid))
        # try:
        #     db.session.merge(km)
        #     db.session.commit()
        # except:
        #     logger.exception("Cannot login the user - uid: %d" % km.killmail_id)
        #     db.session.rollback()


    return render_template('base.html', **{
        'wallet': wallet,
    })



if __name__ == '__main__':
    # for killID in zkill:
    #     killmail.append(json.loads(requests.get('https://zkillboard.com/api/killID/[]/'.format(killID)).content))
    app.run(port=4200, host=config.HOST)
