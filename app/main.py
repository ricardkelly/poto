#!/usr/bin/env python3
import flask
import flask_principal
import flask_saml
import sqlite3
from urllib.parse import urlparse
from os import getenv


APP_ROOT = getenv('POTO_ROOT', '/poto')
DB_PATH = getenv('POTO_DB','data/db.sqlite')
DEFAULT_REDIR = getenv('POTO_DEFAULT',APP_ROOT)
IDP_URI = getenv('POTO_IDP', 'metadata-idp.xml')
DEBUG = getenv('POTO_DEBUG', 'False')

# Override the default handler so we can use a local file rather than a hosted URL
def get_local_metadata(metadata_url):
  return open(metadata_url, "r").read()

flask_saml._get_metadata = get_local_metadata


# 
# Make a random sequence of characters that can be used in a URL without expansion, or be the SECRET_KEY for the session storage
# 
def get_random_string(length):
  from random import choice
  from string import ascii_letters
  s = ''.join(choice(ascii_letters) for i in range(length))
  return s


# 
# Create a new Flask app and add bells and whistles of SAML2
# 
app = flask.Flask(__name__)
principals = flask_principal.Principal(app)
app.config.update({
  'SECRET_KEY': get_random_string(24),
  'SAML_METADATA_URL': IDP_URI,
})
saml = flask_saml.FlaskSAML(app)
create_permission = flask_principal.Permission(flask_principal.RoleNeed('create'))

#
# Hook up events for login and logout via SAML to inform Flask-Principal
#
@flask_saml.saml_authenticated.connect_via(app)
def on_saml_authenticated(sender, subject, attributes, auth):
  flask_principal.identity_changed.send(flask.current_app._get_current_object(), identity=get_identity())

@flask_saml.saml_log_out.connect_via(app)
def on_saml_logout(sender):
  flask_principal.identity_changed.send(flask.current_app._get_current_object(), identity=get_identity()
  )


#
# Provides the users' identity in the application
# 
@principals.identity_loader
def get_identity():
  if 'saml' in flask.session:
    return flask_principal.Identity(flask.session['saml']['subject'])
  else:
    return flask_principal.AnonymousIdentity()

#
# Hook up Flask-Principal events for getting an identity and denying permission
# 
@flask_principal.identity_loaded.connect_via(app)
def on_identity_loaded(sender, identity):
  # If you are authenticated by our IdP then you may create new code->URL mappings
  if not isinstance(identity, flask_principal.AnonymousIdentity):
    identity.provides.add(flask_principal.RoleNeed('create'))

@app.errorhandler(flask_principal.PermissionDenied)
def handle_permission_denied(error):
  deny = 'Permission Denied', 403
  redirect = flask.redirect(flask.url_for('login', next=flask.request.url))
  if isinstance(flask.g.identity, flask_principal.AnonymousIdentity):
    return redirect
  else:
    return deny


# 
# Add the new mapping to the database, replacing code with a random string if it is already in use or is empty/invalid
# 
def createCode(code, url, remote_addr, creator):
  from time import time
  attempts = 0
  if code == None or code == "" or not (code.isalnum() or code.isnumeric()):
    code = get_random_string(6)
  conn = sqlite3.connect(DB_PATH)
  c = conn.cursor()
  while attempts < 3:
    try:
      print(code, url, int(time()), remote_addr, creator)
      c.execute('INSERT INTO mapping VALUES (?, ?, ?, ?, ?)', (code, url, int(time()), remote_addr, creator))
      conn.commit()
      conn.close()
      return code
    except sqlite3.IntegrityError as ex:
      code = get_random_string(6)
      print(code)
      attempts = attempts + 1
  flask.abort(500)


# 
# Remove an existing mapping from the database, presuming it exists and the owner of the mapping is the named user
# 
def deleteCode(code, owner):
  conn = sqlite3.connect(DB_PATH)
  c = conn.cursor()
  c.execute('DELETE FROM mapping WHERE code=? AND owner=?', (code, owner))
  conn.commit()
  conn.close()


def codeAvailable(code):
  conn = sqlite3.connect(DB_PATH)
  row = conn.cursor().execute('SELECT code FROM mapping WHERE code=?', (code, )).fetchone()
  conn.close()
  return row == None


def get_full_url(s):
  url = s
  if urlparse(url).scheme == "":
    url = "http://" + url
  return url


def get_redirect(code):
  conn = sqlite3.connect(DB_PATH)
  c = conn.cursor()
  r = c.execute('SELECT url FROM mapping WHERE code=?', (code, )).fetchone()
  conn.close()
  if r:
    url = get_full_url(r[0])
    return url
  return None
  

def get_owner_codes(owner):
  conn = sqlite3.connect(DB_PATH)
  rows = conn.cursor().execute('SELECT code, url FROM mapping WHERE owner=?', (owner, )).fetchall()
  conn.close()
  return [{'code': r[0], 'url': get_full_url(r[1])} for r in rows]


#
# Run the main entrypoint of the application
# - Only permit users who are authorized in the SAML IdP to access
#
@app.route(APP_ROOT, methods=['GET','POST'])
@create_permission.require()
def do_poto():
  identity = get_identity()
  # Providing a fail-safe in case the authentication and permission process failed in an unexpected way 
  if isinstance(identity, flask_principal.AnonymousIdentity):
    return flask.render_template("noauth.html", app_root=APP_ROOT)

  # If this is a POST then the operation is a 'create'
  if (flask.request.method=="POST"):
    url = flask.request.form.get("url", "")
    code = flask.request.form.get("code")
    if len(url) <= 0:
      flask.abort(400)
    new_code = createCode(code, url, flask.request.remote_addr, get_identity().id)
    return flask.redirect(APP_ROOT)

  # Method must be GET
  # Find out what the user wants to do
  op = flask.request.args.get('op')
  url = flask.request.args.get('url')
  code = flask.request.args.get('code')
  if op == "check":
    if code:
      # if the code already exists then say found
      if codeAvailable(code):
        return ('available', 204)
      else:
        return ('found', 200)
    else:
      # if no code passed, say it is not available
      return ('empty', 200)
#  elif op == "create":
#    createCode(code, url, flask.request.remote_addr, get_identity().id)
  elif op == "delete":
    # We will only delete a code created by the current user
    deleteCode(code, get_identity().id)
  elif op == None:
    return flask.render_template("frontend.html", codes=get_owner_codes(identity.id), identity=identity.id, app_root=APP_ROOT)

  # ignore unknown operations, and redirect back to the front-end
  return flask.redirect(APP_ROOT)


# 
# Anybody can call the redirect
# 
@app.route('/<code>', methods=['GET'])
def do_redirect(code=''):
  dont_redir = code[-1] == "."   # if we have a period at the end of the code, then just render a link rather than doing a redirect
  if dont_redir:
    code = code[:-1]
  url = get_redirect(code)
  if url:
    if dont_redir:
      url = str(flask.escape(url))
      html = "<a href=" + url + ">" + url + "</a>"
      return html
    else:
      return flask.redirect(url, code=301)
  else:
    return flask.render_template("missing.html", app_root=APP_ROOT)


#
# We can set up a default redirect or just go to the front-end
#
@app.route('/', methods=['GET'])
def do_root():
  return flask.redirect(DEFAULT_REDIR)


def create_db():
  conn = sqlite3.connect(DB_PATH)
  c = conn.cursor()
  c.execute('''CREATE TABLE IF NOT EXISTS mapping (code UNIQUE NOT NULL, url, timestamp, ip, owner);''')
  conn.commit()
  conn.close()


if __name__ == '__main__':
  create_db()
  app.run(host='0.0.0.0', port=80, debug=(DEBUG == 'True'))
