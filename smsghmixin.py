#!/usr/bin/env python

__author__ = "Ebot Tabi <ebot.tabi@gmail.com> "
__version__ = "1.0.0"

import urllib
import tornado.ioloop
import tornado.web
import tornado.auth
import tornado.httpclient
import tornado.escape
import tornado.httputil
import logging
from tornado.concurrent import TracebackFuture, chain_future, return_future
from tornado.httputil import url_concat
import urllib

class OAuth2Mixin(object):
    """Abstract implementation of OAuth 2.0.

    Class attributes:

    * ``_OAUTH_AUTHORIZE_URL``: The service's authorization url.
    * ``_OAUTH_ACCESS_TOKEN_URL``:  The service's access token url.
    """
    @return_future
    def authorize_redirect(self, redirect_uri=None, client_id=None,
                           client_secret=None, extra_params=None,
                           callback=None, scope=None, response_type="code"):
        """Redirects the user to obtain OAuth authorization for this service.

        Some providers require that you register a redirect URL with
        your application instead of passing one via this method. You
        should call this method to log the user in, and then call
        ``get_authenticated_user`` in the handler for your
        redirect URL to complete the authorization process.
        """
        args = {
            "redirect_uri": redirect_uri,
            "client_id": client_id,
            "response_type": response_type
        }
        if extra_params:
            args.update(extra_params)
        if scope:
            args['scope'] = ' '.join(scope)
        self.redirect(
            url_concat(self._OAUTH_AUTHORIZE_URL, args))
        callback()

    def _oauth_request_token_url(self, redirect_uri=None, client_id=None,
                                 client_secret=None, code=None,
                                 extra_params=None):
        url = self._OAUTH_ACCESS_TOKEN_URL
        args = dict(
            redirect_uri=redirect_uri,
            code=code,
            client_id=client_id,
            client_secret=client_secret,
        )
        if extra_params:
            args.update(extra_params)
        return url_concat(url, args)

class SMSGHMixin(OAuth2Mixin):
    """ SMSGH OAuth2 Mixin
    """

    _OAUTH_AUTHORIZE_URL = 'https://unity.smsgh.com/oauth'
    _OAUTH_ACCESS_TOKEN_URL = 'https://unity.smsgh.com/oauth/token'
    _API_URL = 'https://api.smsgh.com'

    def get_authenticated_user(self, redirect_uri, client_id, client_secret,
                            code, callback, extra_fields=None):
        """ Handles the login for SMSGH, queries /user and returns a user object
        """
        logging.debug('gau ' + redirect_uri)

        url = self._OAUTH_ACCESS_TOKEN_URL
        http = tornado.httpclient.AsyncHTTPClient()

        args = {
        "redirect_uri": redirect_uri,
        "code": code,
        "client_id": client_id,
        "client_secret": client_secret,
        "grant_type": "authorization_code"
        }
        if extra_fields:
            args.update(extra_fields)
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        post_body = urllib.urlencode(args)
        #print post_body
        req = tornado.httpclient.HTTPRequest(url, 'POST', headers=headers, body=post_body)
        http.fetch(req, self.async_callback(self._on_access_token, redirect_uri, client_id,
                                client_secret, callback))

    def _on_access_token(self, redirect_uri, client_id, client_secret,
                        callback, response):
        #print response.body
        """ callback for authentication url, if successful get the user details """
        if response.error:
            logging.warning('SMSGH auth error: %s' % str(response))
            callback(None)
            return

        args = tornado.escape.parse_qs_bytes(
                tornado.escape.native_str(response.body))

        if 'error' in args:
            logging.error('oauth error ' + args['error'][-1])
            raise Exception(args['error'][-1])

        session = {
            "access_token": args["access_token"][-1],
        }

        self.smsgh_request(path="/v3/account/profile",
            callback=self.async_callback(self._on_get_user_info, callback, session),
            access_token=session["access_token"])

    def _on_get_user_info(self, callback, session, user):
        """ callback for SMSGH request /user to create a user """
        logging.debug('user data from SMSGH ' + str(user))
        if user is None:
            callback(None)
            return
        callback({
            "MobileNumber": user['MobileNumber'],
            "AccountNumber": user['AccountNumber'],
            "Company": user['Company'],
            "Credit": user['Credit'],
            "EmailAddress": user['EmailAddress'],
            "AccountId": user['AccountId'],
            "access_token": session["access_token"],
        })

    def smsgh_request(self, path, callback, access_token=None, method='GET', body=None):
        """ Makes a SMSGH API request, hands callback the parsed data """
        args = {}
        args["access_token"] = access_token
        
        #url = tornado.httputil.url_concat(self._API_URL + path, args)
        url = self._API_URL + path
        logging.debug('request to ' + url)
        http = tornado.httpclient.AsyncHTTPClient()
        if body is not None:
            body = tornado.escape.json_encode(body)
            logging.debug('body is' +  body)
        headers = {"Authorization": "Bearer %s" % access_token}
        req = tornado.httpclient.HTTPRequest(url, method, headers=headers, body=body)
        http.fetch(req, self.async_callback(self._parse_response, callback))

    def _parse_response(self, callback, response):
        """ Parse the JSON from the API """
        if response.error:
            logging.warning("HTTP error from SMSGH: %s", response.error)
            callback(None)
            return
        try:
            json = tornado.escape.json_decode(response.body)
        except Exception:
            logging.warning("Invalid JSON from SMSGH: %r", response.body)
            callback(None)
            return
        if isinstance(json, dict) and json.get("error_code"):
            logging.warning("SMSGH error: %d: %r", json["error_code"],
                            json.get("error_msg"))
            callback(None)
            return
        callback(json)
