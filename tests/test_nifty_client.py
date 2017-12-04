import six
import json
import base64
import hashlib
import unittest
import logging
import email.utils
import httpsig_cffi.sign
from flask import Flask
from flask_cavage import CavageSignature, require_apikey_authentication


class CavageTestCase(unittest.TestCase):
    generic_headers = [
        "date",
        "(request-target)",
        "host"
    ]
    body_headers = [
        "content-length",
        "content-type",
        "digest",
    ]
    required_headers = {
        "get": generic_headers,
        "head": generic_headers,
        "delete": generic_headers,
        "put": generic_headers + body_headers,
        "post": generic_headers + body_headers
    }

    def setUp(self):
        super(CavageTestCase, self).setUp()
        self.debug = False
        self.app = Flask(__name__)
        self.init_app(self.app)
        self.test_client = self.app.test_client()
        self.secret_keys = dict(access_key_1="12345", access_key_2="23232")
        self.test_host_url = "http://localhost"

    def init_app(self, app):
        if self.debug:
            self.app.logger.addHandler(logging.StreamHandler())
            self.app.logger.setLevel(logging.DEBUG)

        cavage_signature = CavageSignature(app)

        @cavage_signature.secret_loader
        def load_secret(access_key):
            app.logger.debug("Loading secret for %s" % access_key)
            # You can store your keys in files, databases, hash tables...
            if access_key in self.secret_keys:
                return self.secret_keys.get(access_key)

        @self.app.route('/hello_world')
        def hello_world():
            return 'Hello, World!'

        @self.app.route('/hello_world_private', methods=['GET', 'POST'])
        @require_apikey_authentication
        def hello_world_private():
            return '<Whisper> Hello, world!'

        @self.app.route('/hello_someone',
                        methods=['GET', 'POST', 'PUT', 'DELETE', 'HEAD'])
        @require_apikey_authentication
        def hello_someone():
            # If we get here, the payload has also been validated
            return 'Hello, Someone!'

    def mk_signer(self, key_id, secret, http_method, algorithm="hmac-sha256"):
        headers = self.required_headers.get(http_method.lower())
        signer = httpsig_cffi.sign.HeaderSigner(
            key_id=key_id, secret=secret,
            algorithm=algorithm, headers=headers)
        return signer

    def compute_checksum(self, body=""):
        # This coerces everything into json.
        return {"digest": "SHA-256=%s" % base64.b64encode(
            hashlib.sha256(body).digest()
        ).decode('utf-8')}

    def mk_headers(self, method, data_dict):
        headers = {
            'date': email.utils.formatdate(usegmt=True),
            "content-type": "application/json"
        }
        if 'host' in self.required_headers.get(method.lower()):
            url_parts = six.moves.urllib.parse.urlparse(self.test_host_url)
            headers['host'] = url_parts.netloc

        if method.lower() in ["put", "post"]:
            body = bytes(json.dumps(data_dict).encode('utf-8'))
            headers.update(self.compute_checksum(body))
            headers["content-length"] = len(body)

        return headers

    def mk_signed_headers(self, access_key, secret, method, path, data):
        signer = self.mk_signer(access_key, secret, method)
        headers = self.mk_headers(method, data)
        signed_headers = signer.sign(
            headers, host=headers.get('host'),
            method=method, path=path)
        return signed_headers

    def test_hello_world_should_not_be_accesible(self):
        rv = self.test_client.get('/hello_world')
        self.assertEquals(rv.status_code, 200)

    def test_protected_resource_should_not_be_accesible_without_signing(self):
        rv = self.test_client.get(
            '/hello_world_private',
            data=json.dumps({}),
            content_type='application/json')
        self.assertEquals(rv.status_code, 401)

    def test_protected_get_resource_should_be_accesible_with_signing(self):
        path = "/hello_world_private"
        access_key = "access_key_1"
        secret = self.secret_keys.get(access_key)
        data = dict()
        signed_headers = self.mk_signed_headers(
            access_key, secret, "get", path, data)
        rv = self.test_client.get(
            path, headers=signed_headers, data=json.dumps(data))
        self.assertEquals(rv.status_code, 200)

    def test_protected_resource_should_be_accesible_with_a_signature_via_a_post_with_json_payload(self):  # noqa
        path = "/hello_someone"
        access_key = "access_key_1"
        secret = self.secret_keys.get(access_key)
        data = dict(username='Mikey')
        signed_headers = self.mk_signed_headers(
            access_key, secret, "post", path, data)
        rv = self.test_client.post(
            path, headers=signed_headers, data=json.dumps(data))
        self.assertEquals(rv.status_code, 200)

    def test_protected_resource_should_be_accesible_with_a_signature_via_a_get_with_query(self):  # noqa
        path = "/hello_world_private?username=Mikey"
        access_key = "access_key_1"
        secret = self.secret_keys.get(access_key)
        data = dict()
        signed_headers = self.mk_signed_headers(
            access_key, secret, "get", path, data)
        rv = self.test_client.get(
            path, headers=signed_headers, data=json.dumps(data))
        self.assertEquals(rv.status_code, 200)

    def test_protected_resource_should_be_accesible_with_a_signature_via_a_put_with_json_payload(self):  # noqa
        path = "/hello_someone"
        access_key = "access_key_1"
        secret = self.secret_keys.get(access_key)
        data = dict(username='Mikey')
        signed_headers = self.mk_signed_headers(
            access_key, secret, "put", path, data)
        rv = self.test_client.put(
            path, headers=signed_headers, data=json.dumps(data))
        self.assertEquals(rv.status_code, 200)

    def test_protected_resource_should_be_accesible_with_a_signature_via_a_delete(self):  # noqa
        path = "/hello_someone?username=Mikey"
        access_key = "access_key_1"
        secret = self.secret_keys.get(access_key)
        data = dict()
        signed_headers = self.mk_signed_headers(
            access_key, secret, "delete", path, data)
        rv = self.test_client.delete(
            path, headers=signed_headers, data=json.dumps(data))
        self.assertEquals(rv.status_code, 200)

    def test_protected_resource_should_be_accesible_with_a_signature_via_a_head(self):  # noqa
        path = "/hello_someone?username=Mikey"
        access_key = "access_key_1"
        secret = self.secret_keys.get(access_key)
        data = dict()
        signed_headers = self.mk_signed_headers(
            access_key, secret, "head", path, data)
        rv = self.test_client.head(
            path, headers=signed_headers, data=json.dumps(data))
        self.assertEquals(rv.status_code, 200)
