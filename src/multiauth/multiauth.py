from urllib.parse import urljoin

from tornado import gen
from tornado.escape import url_escape
from tornado.httputil import url_concat

from traitlets import (
    Unicode, Integer, Dict, TraitError, List, Bool, Any,
    Type, Set, Instance, Bytes, Float,
    observe, default,
)

from jupyterhub.auth import Authenticator
from jupyterhub.handlers.login import LoginHandler, LogoutHandler

from oauthenticator.generic import GenericOAuthenticator
from clb_authenticator import ClbAuthenticator
from firstuseauthenticator.firstuseauthenticator import FirstUseAuthenticator

from escapism import escape

import pdb
import os
import subprocess
import string


class MultiLoginHandler(LoginHandler):
    def _render(self, login_error=None, username=None):
        next=url_escape(self.get_argument('next', default=''))
        return self.render_template(
            'login_multi_eb.html',
            username=username,
            login_error=login_error,
            custom_html=self.authenticator.custom_html,
            login_url=self.settings['login_url'],
            login_services=self.authenticator.login_services(
                self.hub.base_url, next),
            first_use_enabled=self.authenticator.first_use_enabled
        )

class MultiLogoutHandler(LogoutHandler):
    def get(self):
        user = self.get_current_user()
        if user.spawner is not None and user.spawner.active:
            user.spawner.stop()
        if user:
            self.log.info("User logged out: %s", user.name)
            self.clear_login_cookie()
            self.statsd.incr('logout')
        if self.authenticator.auto_login:
            html = self.render_template('logout.html')
            self.finish(html)
        else:
            self.redirect(self.settings['login_url'], permanent=False)

class MultiAuthenticator(Authenticator):

    user_data_location = Unicode(
        config=True,
        help="""The file path where the user persistent files will be stored""")

    first_use_auth = Instance(Authenticator)
    hbp_auth = Instance(Authenticator)
    ebrains_auth = Instance(Authenticator)

    hbp_prefix = Unicode("hbp", help='The path to the HBP service', config=True)
    ebrains_prefix = Unicode("ebrains", help='The path to the EBrains service', config=True)

    first_use_enabled = Bool(
        False,
        config=True,
        help="Allow first-use authentication",
    )

    @default('first_use_auth')
    def _default_first_use_auth(self):
        return FirstUseAuthenticator(parent=self)

    @default('hbp_auth')
    def _default_hbp_auth(self):
        return GenericOAuthenticator(parent=self)

    @default('ebrains_auth')
    def _default_ebrains_auth(self):
        return ClbAuthenticator(parent=self)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.__client_id = None
        self.__client_secret = None
        self.__scope = None
        self.__authorize_url = None

    def _user_exists(self, user):
        return self.first_use_auth._user_exists(user)

    @property
    def client_id(self):
        return self.__client_id

    @property
    def client_secret(self):
        return self.__client_secret

    @property
    def scope(self):
        return self.__scope

    @property
    def authorize_url(self):
        return self.__authorize_url


    def set_oauth_tokens(self, subauth):
        """
        Caches configured information from the subauthenticator in properties
        """
        self.__client_id = subauth.client_id
        self.__client_secret = subauth.client_secret
        self.__scope = subauth.scope
        self.__authorize_url = subauth.authorize_url

    def get_callback_url(self, handler=None):
        """
        This is called by oauth2, it thinks that there will just be one 
        """
        if handler is None:
            raise ValueError("There must be a handler!")

        if self.hbp_prefix in handler.request.path:
            self.set_oauth_tokens(self.hbp_auth)
            return self.hbp_auth.get_callback_url(handler)
        if self.ebrains_prefix in handler.request.path:
            self.set_oauth_tokens(self.ebrains_auth)
            return self.ebrains_auth.get_callback_url(handler)
        raise Exception("Unknown handler request path {}".format(handler.request.path))

    def validate_username(self, username):
        return self.first_use_auth.validate_username(username)

    def __get_login_url(self, auth, prefix, base_url, next):
        login_url = auth.login_url(base_url + prefix)
        return url_concat(login_url, {"next": next})

    def login_services(self, base_url, next):
        return [
            (self.ebrains_auth.login_service, self.__get_login_url(
                self.ebrains_auth, self.ebrains_prefix, base_url, next)),
            (self.hbp_auth.login_service, self.__get_login_url(
                self.hbp_auth, self.hbp_prefix, base_url, next))
        ]

    def __prepend_urls(self, urls, pre):
        preurls = [("/" + pre + url, handler) for url, handler in urls]
        # self.log.info("Original Urls: {} Prefix: {} Prepended urls: {}".format(urls, pre, preurls))
        return preurls

    def get_handlers(self, app):
        h = [
            ('/login', MultiLoginHandler),
            ('/logout', MultiLogoutHandler),
        ]
        hbp_handlers = self.hbp_auth.get_handlers(app)
        ebrains_handlers = self.ebrains_auth.get_handlers(app)
        h.extend(self.__prepend_urls(hbp_handlers, self.hbp_prefix))
        h.extend(self.__prepend_urls(ebrains_handlers, self.ebrains_prefix))
        if self.first_use_enabled:
            h.extend(self.first_use_auth.get_handlers(app))
        self.log.info("Handlers: {}".format(h))
        return h

    def _mkdir(self, dir):
        if not os.path.exists(dir):
            os.mkdir(dir)

    def _escape(self, s):
        """Escape a string to docker-safe characters"""
        return escape(
            s.lower(),
            safe=string.ascii_letters + string.digits + '-',
            escape_char='_',
        )

    async def authenticate(self, handler, data):
        """
        Delegate authentication to the appropriate authenticator
        """
        if self.hbp_prefix in handler.request.path:
            result = await self.hbp_auth.authenticate(handler, data)
        elif self.ebrains_prefix in handler.request.path:
            result = await self.ebrains_auth.authenticate(handler, data)
        elif self.first_use_enabled:
            result = await self.first_use_auth.authenticate(handler, data)

        # If error, return
        if result is None:
            return result

        # Make directories to store user files
        username = result
        if isinstance(result, dict):
            username = result["name"]
        escaped_name = self._escape(username)
        user_persist_data = os.path.join(self.user_data_location, escaped_name)
        self._mkdir(user_persist_data)
        subprocess.run([
            "sudo", "chown", "1000:100", user_persist_data
        ])

        return result
