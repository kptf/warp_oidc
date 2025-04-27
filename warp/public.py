# public parts
import flask
bp = flask.Blueprint('public', __name__)

# redirect to your main imprint source/page
@bp.route('/imprint')
def imprint():
    imprint_redirect_url = flask.current_app.config.get('IMPRINT_REDIRECT_URL')
    return flask.redirect(imprint_redirect_url)

# redirect to your main data privacy source/page
@bp.route('/privacy')
def data_privacy():
    data_privacy_redirect_url = flask.current_app.config.get('DATA_PRIVACY_REDIRECT_URL')
    return flask.redirect(data_privacy_redirect_url)
