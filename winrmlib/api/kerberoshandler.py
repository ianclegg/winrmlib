# import suds.transport.https
# import suds.transport.http
#
# #!/usr/bin/python
#
# # urllib2 GSS-API (SPNEGO) using PyKerberos
#
# # Licensed under the Apache License, Version 2.0 (the "License");
# # you may not use this file except in compliance with the License.
# # You may obtain a copy of the License at
# #     http://www.apache.org/licenses/LICENSE-2.0
# # Unless required by applicable law or agreed to in writing, software
# # distributed under the License is distributed on an "AS IS" BASIS,
# # WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# # See the License for the specific language governing permissions and
# # limitations under the License.
#
# import re
# import logging
# import kerberos
# from urllib2 import BaseHandler
# from urllib2 import HTTPPasswordMgr
#
# def getLogger():
#     log = logging.getLogger("http_kerberos_auth_handler")
#     handler = logging.StreamHandler()
#     formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
#     handler.setFormatter(formatter)
#     log.addHandler(handler)
#     return log
#
# log = getLogger()
# log.setLevel(logging.ERROR)
#
#
# class BaseKerberosHandler(BaseHandler):
#     """auth handler for urllib2 that does Kerberos HTTP Negotiate
#     Authentication
#     """
#
#     def negotiate_value(self, headers):
#         """checks for "Negotiate" in proper auth header
#         """
#         authreq = headers.get(self.auth_header, None)
#         log.debug('authreq = {0}'.format(authreq))
#
#         if authreq:
#             rx = re.compile(r'(?:.*,)*\s*Negotiate\s*([^,]*),?', re.I)
#             mo = rx.search(authreq)
#             if mo:
#                 return mo.group(1)
#             else:
#                 log.debug("regex failed on: %s" % authreq)
#
#         else:
#             log.debug("%s header not found" % self.auth_header)
#
#         return None
#
#     def __init__(self, password_mgr=None):
#         if password_mgr is None:
#             password_mgr = HTTPPasswordMgr()
#         self.retried = 0
#         self.context = None
#         self.password = password_mgr
#         self.add_password = self.password.add_password
#
#     def generate_request_header(self, req, headers, neg_value):
#         self.retried += 1
#         log.debug("retry count: %d" % self.retried)
#
#         host = req.get_host()
#         log.debug("req.get_host() returned %s" % host)
#
#         # Build the service name
#         if self.service is None:
#             self.service = "HTTP@%s" % host.rsplit(':', 1)[0]
#
#         # User credentials are in the Password Manager
#         log.debug("Finding credentials for url: %s" % req.get_full_url())
#         user, password = self.password.find_user_password(None, req.get_full_url())
#
#         # TODO: Enusre a TGT for the user principal exists, if not, use the password
#         # TODO: to aquire one.
#         # We currently rely on Nico's pykerberos patch to do this, one day it might be
#         # nice to do this using the open source kerbeos gss api 'C' libraries
#
#
#         # An empty username will attempt the current user
#         log.debug("Intialising Kerberos Context, service: %s UPN: %s" % (self.service, user))
#         result, self.context = kerberos.authGSSClientInit(self.service, user, password=password)
#
#         if result < 0:
#             log.warning("authGSSClientInit returned result %d" % result)
#             return None
#
#         log.debug("authGSSClientInit() succeeded")
#
#         result = kerberos.authGSSClientStep(self.context, neg_value)
#
#         if result < 0:
#             log.warning("authGSSClientStep returned result %d" % result)
#             return None
#
#         log.debug("authGSSClientStep() succeeded")
#
#         response = kerberos.authGSSClientResponse(self.context)
#         log.debug("authGSSClientResponse() succeeded")
#
#         return "Negotiate %s" % response
#
#     def authenticate_server(self, headers):
#         neg_value = self.negotiate_value(headers)
#         if neg_value is None:
#             log.critical("mutual auth failed. No negotiate header")
#             return None
#
#         result = kerberos.authGSSClientStep(self.context, neg_value)
#
#         if result < 1:
#             # this is a critical security warning
#             # should change to a raise --Tim
#             log.critical(
#                 "mutual auth failed: authGSSClientStep returned result %d" %
#                 result)
#
#     def clean_context(self):
#         if self.context is not None:
#             log.debug("cleaning context")
#             kerberos.authGSSClientClean(self.context)
#             self.context = None
#
#     def http_error_auth_reqed(self, host, req, headers):
#         neg_value = self.negotiate_value(headers)  # Check for auth_header
#         if neg_value is not None:
#             if not self.retried > 0:
#                 return self.retry_http_kerberos_auth(req, headers, neg_value)
#             else:
#                 return None
#         else:
#             self.retried = 0
#
#     def https_request(self, req):
#         neg_hdr = self.generate_request_header(req, None, '')
#         req.add_unredirected_header(self.authz_header, neg_hdr)
#         return req
#
#     def retry_http_kerberos_auth(self, req, headers, neg_value):
#         try:
#             neg_hdr = self.generate_request_header(req, headers, neg_value)
#
#             if neg_hdr is None:
#                 log.debug("neg_hdr was None")
#                 return None
#
#             req.add_unredirected_header(self.authz_header, neg_hdr)
#             resp = self.parent.open(req)
#
#             if resp.getcode() != 200:
#                 self.authenticate_server(resp.info())
#
#             return resp
#
#         except kerberos.GSSError, e:
#             self.clean_context()
#             self.retried = 0
#             log.critical("GSSAPI Error: %s/%s" % (e[0][0], e[1][0]))
#             return None
#
#         self.clean_context()
#         self.retried = 0
#
#
# class ProxyKerberosAuthHandler(BaseKerberosHandler):
#     """Kerberos Negotiation handler for HTTP proxy auth
#     """
#
#     authz_header = 'Proxy-Authorization'
#     auth_header = 'proxy-authenticate'
#
#     handler_order = 480  # before Digest auth
#
#     def http_error_407(self, req, fp, code, msg, headers):
#         log.debug("inside http_error_407")
#         host = req.get_host()
#         retry = self.http_error_auth_reqed(host, req, headers)
#         self.retried = 0
#         return retry
#
#
# class HTTPKerberosAuthHandler(BaseKerberosHandler):
#     """Kerberos Negotiation handler for HTTP auth
#     """
#
#     authz_header = 'Authorization'
#     auth_header = 'www-authenticate'
#
#     handler_order = 480  # before Digest auth
#
#     def __init__(self, service, keytab, pm):
#         # TODO: If the service is not set seach for it. If we still not found
#         # then we will try the standard service HTTP@fqdn
#         BaseKerberosHandler.__init__(self, pm)
#         self.service = service
#         self.keytab = keytab
#
#     def http_error_401(self, req, fp, code, msg, headers):
#         log.debug("inside http_error_401")
#         host = req.get_host()
#         retry = self.http_error_auth_reqed(host, req, headers)
#         self.retried = 0
#         return retry
#
#
# class KerberosHttpAuthenticated(suds.transport.https.HttpAuthenticated):
#     """
#     Provides Kerberos http authentication.
# 	    - service = kerberos service name (HTTP@hostname)
# 		- keytab
#     """
#
#     def __init__(self, **kwargs):
#         self.service = kwargs.get('service', None)
#         self.keytab = kwargs.get('keytab',None)
#         suds.transport.https.HttpAuthenticated.__init__(self, **kwargs)
#
#     def u2handlers(self):
#         handlers = suds.transport.http.HttpTransport.u2handlers(self)
#         handlers.append(HTTPKerberosAuthHandler(self.service, self.keytab, self.pm))
#         return handlers