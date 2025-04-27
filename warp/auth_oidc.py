# fully based on auth_ldap.py! I adapted it for oidc!
import os
from urllib.parse import urlparse
from peewee import fn
import flask
from warp.db import *
import warp.auth
from . import utils

# import request to pass non-oidc auths etc.
from flask import request

# import OAuth; requires pip install Flask-OIDC => already added to requirements file
from authlib.integrations.flask_client import OAuth


bp = flask.Blueprint('auth', __name__)

# renamed and modified ldapApplyUserMetadata function
def oidc_apply_user_login_data(login_data):
    # get details
    login = login_data['login']
    name = login_data['name']
    groups = login_data['groups']
    oidc_groups = login_data['oidc_groups']


    with DB.atomic():
        # get user
        db_user = Users.select().where(Users.login == login).dicts().get()

        if db_user is None:
            # create user if not already in database
            Users.insert({
                Users.login: login,
                Users.name: name,
                Users.account_type: ACCOUNT_TYPE_USER,
                Users.password: '*'
            }).execute()

            # reget user for getting details like account_type below
            db_user = Users.select().where(Users.login == login).dicts().get()
        elif db_user.get("name") != name:
            # update user's name in case of changes
            Users.update({
                Users.name: name
            }).where(Users.login == login).execute()


        # set/change account_type based on provided groups
        #ACCOUNT_TYPE_ADMIN = 10
        #ACCOUNT_TYPE_USER = 20
        #ACCOUNT_TYPE_BLOCKED = 90
        #ACCOUNT_TYPE_GROUP = 100
        current_account_type = db_user.get("account_type")

        # THIS IS OLD CODE; IT WAS USED TO ACTIVELY SET USERS AS BLOCKED; THIS WAS HOWEVER COMMENTED OUT BECAUSE
        # THE NORMAL LOGIN LOGIC SHOULD HANDEL NON-ALLOWED LOGINS, SO NO NEED TO BLOCK THEM ACTIVELY!
        # ALSO, THE CONFIG VAR "OIDC_GROUPS_ALLOWED_USERS" IS NOT IN USE ANYMORE!
        #
        # check for block
        # user_is_blocked = current_account_type == ACCOUNT_TYPE_BLOCKED
        # groups_allowed_users = flask.current_app.config.get('OIDC_GROUPS_ALLOWED_USERS', [])
        # if not isinstance(groups_allowed_users, list):
        #     groups_allowed_users = flask.current_app.config['OIDC_GROUPS_ALLOWED_USERS'] = [groups_allowed_users]
        #
        # if not groups_allowed_users is None and len(groups_allowed_users) > 0:
        #     user_has_any_allowed_group = "*" in groups_allowed_users or set(groups_allowed_users) & set(groups)
        #     if not user_has_any_allowed_group and not user_is_blocked:
        #         print(f'BLOCKING {login}')
        #         Users.update({
        #             Users.account_type: ACCOUNT_TYPE_BLOCKED
        #         }).where(Users.login == login).execute()
        #     elif user_has_any_allowed_group and user_is_blocked:
        #         print(f'UNBLOCKING {login}')
        #         Users.update({
        #             Users.account_type: ACCOUNT_TYPE_USER
        #         }).where(Users.login == login).execute()


        # check for admin user type and set it accordingly in case of changes
        user_is_admin = current_account_type == ACCOUNT_TYPE_ADMIN
        groups_admin_users = flask.current_app.config.get('OIDC_GROUPS_ADMIN_USERS', [])
        if not isinstance(groups_admin_users, list):
            groups_admin_users = flask.current_app.config['OIDC_GROUPS_ADMIN_USERS'] = [groups_admin_users]

        if not groups_admin_users is None and len(groups_admin_users) > 0:
            user_has_any_admin_group = "*" in groups_admin_users or len(set(groups_admin_users) & set(oidc_groups)) > 0
            if not user_has_any_admin_group and user_is_admin:
                print(f'Setting account_type = User to {login}')
                Users.update({
                    Users.account_type: ACCOUNT_TYPE_USER
                }).where(Users.login == login).execute()
            elif user_has_any_admin_group and not user_is_admin:
                print(f'Setting account_type = Admin to {login}')
                Users.update({
                    Users.account_type: ACCOUNT_TYPE_ADMIN
                }).where(Users.login == login).execute()

        # check user's group assignment
        existing_groups = Users.select( Users.login ) \
            .where( Users.account_type == ACCOUNT_TYPE_GROUP ) \
            .where(fn.LOWER(Users.login).in_([g.lower() for g in groups])) \
            .tuples()
        existing_groups = [i[0] for i in existing_groups]

        if len(existing_groups) != len(groups):
            non_matching_groups = [item for item in groups if item not in existing_groups]
            print("OIDC WARNING: some of the groups defined in OIDC and mapped via OIDC_GROUP_MAP don't exist in Warp")

        insertData = [ {Groups.login: login, Groups.group: i} for i in existing_groups ]
        #TODO: check if the materialized view is updated if no changes
        # => I have to admit I didn't really know what to do with this, so I just kept waiting until it's in a new release of the mail repo
        Groups.insert(insertData).on_conflict_ignore().execute()

        strictMapping = flask.current_app.config.get('OIDC_GROUP_STRICT_MAPPING', True)
        if strictMapping:
            Groups.delete() \
                .where( Groups.login == login ) \
                .where( Groups.group.not_in(existing_groups) ) \
                .execute()


# a modification of the original ldapGetUserMetadata function;
# this was changed a bit because of the logic of oidc compared to ldap
def oidc_get_user_login_data(user_data):
    # set main return vars
    login_allowed = False
    login_error = None
    login_data = {}

    # check if user_data was passed
    if user_data is None:
        login_error = f'NO DATA WAS PASSED VIA OIDC! LOGIN NOT POSSIBLE!'
        print(f'ERROR: {login_error}')
        return False, login_error, login_data

    # get login attribute (used in warp's db)
    oidc_user_name_att = flask.current_app.config.get('OIDC_USER_NAME_ATTRIBUTE', 'email')
    login = user_data.get(oidc_user_name_att)
    if login is None:
        login_error = f'NO {oidc_user_name_att} WAS PASSED VIA OIDC! LOGIN NOT POSSIBLE!'
        print(f'ERROR: {login_error}')
        return False, login_error, login_data

    # get name attribute (used in warp's db)
    oidc_name_att = flask.current_app.config.get('OIDC_NAME_ATTRIBUTE', 'name')
    name = user_data.get(oidc_name_att)
    if name is None:
        print(f'WARNING: NO {oidc_name_att} WAS PASSED VIA OIDC!')

    # checking group map
    oidc_group_map = flask.current_app.config.get('OIDC_GROUP_MAP', [[None, None]])
    if isinstance(oidc_group_map, str):
        # parse the var in case it's still a string (I didn't want to change too much in the original code, so this is done here once)
        oidc_group_map = oidc_group_map.replace("null", "None").replace("'", '"').replace(":", ",")
        try:
            oidc_group_map = eval(oidc_group_map)
            flask.current_app.config['OIDC_GROUP_MAP'] = oidc_group_map
        except Exception:
            login_error = f"COULD NOT PARSE YOUR 'OIDC_GROUP_MAP' SETTING: {oidc_group_map} => LOGIN PREVENTED!"
            print(f'ERROR: {login_error}')

            if not flask.current_app.debug:
                # this error should not be displayed in production
                login_error = f"UNKNOWN LOGIN ERROR, PLEASE CONTACT ADMINISTRATOR!"

            return False, login_error, login_data

    # get passed oidc groups (these are also passed on further for setting the user/admin account type!)
    oidc_groups = user_data.get("groups")

    if oidc_groups is None and (not oidc_group_map is None or len(oidc_group_map) > 0):
        oidc_groups = []
        print(f'ERROR: NO "groups" WERE PASSED VIA OIDC! => CONTINUE WITHOUT GROUPS!')


    # set result login data
    login_data = {
        "login": login,
        "name": name,
        "groups": [],
        "oidc_groups": oidc_groups
    }

    # this is mainly the "LDAP group mapping" logic from the original ldapGetUserMetadata function.
    # Instead of using continue I used an if/elif/else logic, but it does the same
    for oidc_group, warp_group in oidc_group_map:
        # case 4: [null,null]
        # => every OIDC user will be allowed to log in to Warp
        if oidc_group is None and warp_group is None:
            login_allowed = True

        # case 3: [null,'OIDC group A']
        # => user will be also accordingly added to OIDC group A
        elif oidc_group is None:
            login_data["groups"].append(warp_group)

        # case 1: ['OIDC group 1',null]
        # => User must be in one of the OIDC group 1 to be allowed to log in to Warp
        elif not oidc_group is None and warp_group is None:
            if oidc_group in oidc_groups:
                login_allowed = True


        else: #case 2: ['OIDC group 1','WARP group A']
            if oidc_group in oidc_groups:
                login_data["groups"].append(warp_group)

    return login_allowed, login_error, login_data


# adapted from the original ldapLogin function;
# this is also a bit different due to how oidc works
def oidc_login(user_data):
    login_allowed, login_error, login_data = oidc_get_user_login_data(user_data)

    if login_error is None and login_allowed is True:
        oidc_apply_user_login_data(login_data)

        flask.session['login'] = login_data['login'] # set "admin" here for testing only!
        flask.session['login_time'] = utils.now()

    return login_allowed, login_error, login_data


# adapted from the original login function
@bp.route('/login', methods=['GET', 'POST'])
def login():

    # check for non-oidc login and correct domain for oidc callback
    http_method = request.method
    referrer = request.referrer
    host_url = request.host_url
    parsed_host_url = urlparse(host_url)
    host = parsed_host_url.netloc
    oidc_callback_uri = flask.current_app.config["OIDC_REDIRECT_URI"]
    parsed_oidc_callback_uri = urlparse(oidc_callback_uri)
    oidc_callback_host = parsed_oidc_callback_uri.netloc

    # check for imprint and data privacy urls
    display_imprint = flask.current_app.config.get('DISPLAY_IMPRINT')
    display_data_privacy = flask.current_app.config.get('DISPLAY_DATA_PRIVACY')

    # get eventually passed user from non-oidc login
    u = flask.request.form.get('login')

    # checks if a non-oidc user want to log in and in that case pass it on to the original auth.login()
    if http_method == "POST" and not u is None or (not referrer is None and referrer.endswith('/login-non-oidc')):
        oidc_excluded_users = flask.current_app.config.get('OIDC_EXCLUDED_USERS', [])
        if u in oidc_excluded_users:
            return warp.auth.login()
        else:
            flask.flash(f'User {u} is not allowed to log in!', 'danger')

            return flask.render_template('login.html', display_imprint=display_imprint, display_data_privacy=display_data_privacy)
    else:
        # check if a login button page is configured to be shown; is skipped in case of respective redirects etc.
        if http_method == "GET" and flask.current_app.config.get('OIDC_SHOW_LOGIN_BUTTON', False):
            if referrer is None or (not referrer.endswith('/logout') and not referrer.endswith('/login')):
                return flask.render_template('login_oidc.html', display_imprint=display_imprint, display_data_privacy=display_data_privacy)

    if not host.lower() == oidc_callback_host.lower():
        base_url = request.base_url
        redirect_url = base_url.replace(host, oidc_callback_host)
        print(f'REDIRECTING USER FROM {base_url} TO {redirect_url} TO MATCH CONFIGURED OIDC CALLBACK DOMAIN OF CALLBACK URL {oidc_callback_uri}  => RE-LOGIN REQUIRED BUT PREVENTS ERROR 502 BAD GATEWAY')
        return flask.redirect(redirect_url)

    # clear session to force re-login
    flask.session.clear()

    # create nonce required for oidc/oauth and store it
    nonce = os.urandom(16).hex()
    flask.session["oidc_nonce"] = nonce
    oauth = get_oauth()
    return oauth.microsoft.authorize_redirect(flask.current_app.config["OIDC_REDIRECT_URI"], nonce=nonce)


# method to pass requests of non-oidc logins to auth.login()
@bp.route('/login-non-oidc', methods=['GET', 'POST'])
def login_non_oidc():
    return warp.auth.login()


# callback logic of oidc;
# a bit of the original ldapLogin logic had to be moved here due to how oidc works;
# the callback url is set to a fixed route ("protocol://host:port/......./oidc/callback") here; this is what needs to be set at the oidc!
@bp.route("/oidc/callback")
def oidc_callback():
    oauth = get_oauth()
    token = oauth.microsoft.authorize_access_token()
    nonce = flask.session.pop("oidc_nonce", None)
    if not nonce:
        return "Nonce missing. Possible replay attack!", 400

    # use this for dev/debug only!
    #print(f'ACCESS TOKEN: {token["access_token"]}')
    #print(f'ID TOKEN: {token["id_token"]}')

    # Parse the ID token with proper key validation
    user_data = oauth.microsoft.parse_id_token(token, nonce=nonce)
    login_allowed, login_error, login_data = oidc_login(user_data)

    if login_allowed:
        # currently there is no flask on view.index (?)
        #name = login_data.get("name")
        #email = login_data.get("email", "no email!")
        #flask.flash(f"Logged in as: {name} ({email})")

        return flask.redirect(flask.url_for('view.index'))

    elif not login_error is None:
        flask.flash(
            f'<div><span class="TR">THERE WAS THE FOLLOWING LOGIN ERROR:</span> <span class="TR">{login_error}</span></div>'
            f'<div><span class="TR">In case you want to try again use the button below</span></div>'
        )
        return flask.redirect('view.login')

    else: #just login_allowed=False
        flask.flash(
            f'<div><span class="TR">USER</span> {login_data.get("login")} | {login_data.get("name")} <span class="TR">IS NOT ALLOWED TO LOGIN!</div>'
            f'<div><span class="TR">In case you want to try again use the button below</span></div>'
        )
        return flask.redirect('view.login')


# basically the singleton pattern of creating the oauth object;
# this is done here once to keep code changes to other files a minimal as possible
def get_oauth():
    if not hasattr(flask.current_app, "oauth"):
        flask.current_app.oauth = setup_oidc_connection()

    return flask.current_app.oauth


# initial setup done in the course of get_oauth to create the oauth object needed for oidc
def setup_oidc_connection():
    print(f'SETTING UP OIDC CONNECTION FOR {flask.current_app}...')

    # get all necessary settings from config
    oidc_type = flask.current_app.config.get('OIDC_TYPE', "generic")
    client_id = flask.current_app.config.get("OIDC_CLIENT_ID")
    client_secret = flask.current_app.config.get("OIDC_CLIENT_SECRET")
    tenant_id = flask.current_app.config.get("OIDC_TENANT_ID")
    server_metadata_url = flask.current_app.config.get("OIDC_DISCOVERY_URL", f'https://login.microsoftonline.com/{tenant_id}/v2.0/.well-known/openid-configuration')
    scope = flask.current_app.config.get("OIDC_SCOPE", "openid email profile")

    if not oidc_type == "microsoft":
        print(f'WARNING: OIDC has not been tested with other providers than "microsoft" yet! It should work, but as said: No guarantee it does... sry!')
    else:
        if server_metadata_url is None and not tenant_id is None:
            server_metadata_url = f'https://login.microsoftonline.com/{tenant_id}/v2.0/.well-known/openid-configuration'

    if client_id is None or client_secret is None or server_metadata_url is None:
        error_msg = f'OIDC CONFIGURATION (PARTLY) MISSING; ENSURE SETTING OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, OIDC_DISCOVERY_URL/OIDC_TENANT_ID IN CONFIG!'
        print(f'ERROR: {error_msg}')
        raise Exception(error_msg)

    # create the oauth object
    oauth = OAuth(flask.current_app)
    oauth.register(
        name=oidc_type,
        client_id=client_id,
        client_secret=client_secret,
        server_metadata_url=server_metadata_url,  # Fetch metadata dynamically
        client_kwargs={"scope": scope},
    )

    return oauth


# removed reference to original logout as an own logout page is needed;
# (otherwise you would stick in a loop as you'd get loggedin automatically if you'd disable the login button page
# bp.route('/logout')(warp.auth.logout)
def logout():
    flask.session.clear()
    return flask.render_template('logout.html')
    #return f'You have been logged out! Go to <a href="/">HOME</a> again :)', 200
bp.route('/logout')(logout)


bp.before_app_request(warp.auth.session)