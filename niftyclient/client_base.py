import email.utils
import requests
from .signed_request_auth import SignedRequestAuth
from . import exceptions


class ClientBase(object):
    def __init__(self, config, logger):
        self.logger = logger
        self.config = config
        if not hasattr(self.config, 'api_base'):
            self.config.api_base = 'http://api.integ.nifty.co.ke/api/v1'

    @property
    def user_url(self):
        return '{self.config.api_base}/user/{self.config.user_id}'.format(
            self=self
        )

    @property
    def wallet_url(self):
        return '{self.user_url}/wallet'.format(self=self)

    @property
    def c2b_url(self):
        return '{self.user_url}/mpesa/c2b-confirmation'.format(self=self)

    @property
    def online_checkout_url(self):
        return '{self.user_url}/mpesa/online-checkout'.format(self=self)

    @property
    def headers(self):
        return {
            "date": email.utils.formatdate(usegmt=True),
            "content-type": "application/json"
        }

    @property
    def auth(self):
        return SignedRequestAuth(self.config.key_id, self.config.secret)

    def log_response(self, request):
        self.logger.info(
            "%s request to: %s " % (request.request.method, request.url)
        )
        self.logger.debug("Headers: %s" % request.request.headers)
        self.logger.debug("Content: %s" % request.content)

    def process_response(self, response, schema_factory):
        self.log_response(response)
        try:
            return schema_factory.load(response.json()).data
        # Catches simplejson & stdlib decode errors (requests uses either)
        except ValueError as exc:
            self.logger.exception(
                "Unable to parse response '%s'. Is it JSON?" % response.content
            )
            raise exceptions.ResponseFormatError(exc)
        except requests.exceptions.HTTPError as exc:
            self.logger.exception(
                "HTTP Response Fail: %s Content: %s" % (exc, response.content))
            if response.status_code == 401:
                raise exceptions.AuthenticationError(exc)
            raise exceptions.ResponseError(exc)
        except Exception as exc:
            self.logger.exception(
                "Unhandled Exception: %s Content:%s " % (exc, response.content)
            )
            raise exceptions.NiftyBaseError(exc)
