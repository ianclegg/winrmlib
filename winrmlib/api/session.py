# (c) 2015, Ian Clegg <ian.clegg@sourcewarp.com>
#
# winrmlib is licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
__author__ = 'ian.clegg@sourcewarp.com'

import uuid
from winrmlib.api.service import Service
from winrmlib.api.resourcelocator import ResourceLocator

try:
    from collections import OrderedDict
except ImportError:
    from ordereddict import OrderedDict


class Session(object):
    """
    Factory object for building sessions and connection options
    """

    def __init__(self, endpoint, username, password, **kwargs):
        # transport = Session._build_transport(endpoint, auth, username, password)

        # Store the endpoint and the service we will use to invoke it
        self.endpoint = endpoint
        # False == No CredSSP
        self.service = Service(endpoint, username, password, True)

        # The user can set override some defaults for the Session, they can also be overridden on each request
        self.max_envelope = self._build_max_envelope(kwargs.get('max_envelope_size', Session.MaxEnvelopeSize))
        self.locale = self._build_locale(kwargs.get('locale', Session.Locale))

        # The operation timeout header overrides the timeout set on the server. Some users may prefer to
        # use the servers default timeout, so this header will only be included if the user explicitly sets
        # an operation timeout.
        if 'operation_timeout' in kwargs:
            self.default_operation_timeout = self._build_operation_timeout(kwargs.get('operation_timeout'))
        else:
            self.default_operation_timeout = None

    def get(self, resource, operation_timeout=None, max_envelope_size=None, locale=None):
        """
        resource can be a URL or a ResourceLocator
        """
        if isinstance(resource, str):
            resource = ResourceLocator(resource)

        headers = self._build_headers(resource, Session.GetAction, operation_timeout, max_envelope_size, locale)
        self.service.invoke.set_options(tsoapheaders=headers)
        return self.service.invoke

    def put(self, resource, obj,
            operation_timeout=None, max_envelope_size=None, locale=None):
        """
        resource can be a URL or a ResourceLocator
        """
        headers = None
        return self.service.invoke(headers, obj)

    def delete(self, resource, operation_timeout=None, max_envelope_size=None, locale=None):
        """
        resource can be a URL or a ResourceLocator
        """
        if isinstance(resource, str):
            resource = ResourceLocator(resource)

        headers = self._build_headers(resource, Session.DeleteAction,
                                      operation_timeout, max_envelope_size, locale)
        return self.service.invoke(headers, None)

    def create(self, resource, obj,
               operation_timeout=None, max_envelope_size=None, locale=None):
        """
        resource can be a URL or a ResourceLocator
        """
        if isinstance(resource, str):
            resource = ResourceLocator(resource)

        headers = self._build_headers(resource, Session.CreateAction,
                                      operation_timeout, max_envelope_size, locale)
        return self.service.invoke(headers, obj)

    def command(self, resource, obj,
                operation_timeout=None, max_envelope_size=None, locale=None):
        """
        resource can be a URL or a ResourceLocator
        """
        if isinstance(resource, str):
            resource = ResourceLocator(resource)

        headers = self._build_headers(resource, Session.CommandAction,
                                      operation_timeout, max_envelope_size, locale)
        return self.service.invoke(headers, obj)

    def recieve(self, resource, obj,
                operation_timeout=None, max_envelope_size=None, locale=None):
        """
        resource can be a URL or a ResourceLocator
        """
        if isinstance(resource, str):
            resource = ResourceLocator(resource)

        headers = self._build_headers(resource, Session.ReceiveAction,
                                      operation_timeout, max_envelope_size, locale)
        return self.service.invoke(headers, obj)

    @staticmethod
    def _build_selectors(selectors):
        # Build the WSMan SelectorSet Element from the selector dictionary
        selector_set = []
        for selector_name in selectors.iterkeys():
            selector_value = selectors[selector_name]
            selector_set.append({'#text': str(selector_value), '@Name': selector_name})
        return {'w:SelectorSet': {'w:Selector': selector_set}}

    @staticmethod
    # TODO add mustcomply attribute to element
    def _build_options(options):
        option_set = []
        for name, (value, must_comply) in options.iteritems():
            must_comply = bool(must_comply)
            option_set.append({'#text': str(value), '@Name': name})
        return {'w:OptionSet': {'w:Option': option_set}}

    def _build_operation_timeout(self, operation_timeout):
        if operation_timeout is None:
            return self.default_operation_timeout
        else:
            return {'w:OperationTimeout': 'PT{0}S'.format(operation_timeout)}

    def _build_max_envelope(self, max_envelope_size):
        if max_envelope_size is None:
            return self.max_envelope
        else:
            return {'w:MaxEnvelopeSize': '{0}'.format(max_envelope_size)}

    def _build_locale(self, locale):
        if locale is None:
            return self.locale
        else:
            return {'Locale': {"@xml:lang": "en-US"}}

    def _build_headers(self, resource, action, operation_timeout, max_envelope_size, locale):
        headers = OrderedDict([
            ('a:To', self.endpoint),
            ('a:ReplyTo', Session.Address),
            ('w:ResourceURI', resource.url),
            ('a:MessageID', format(uuid.uuid4())),
            ('a:Action', action)]
        )
        # TODO: Implement support for Microsoft XPRESS compression
        # https://social.msdn.microsoft.com/Forums/en-US/501e4f29-edfc-4240-af3b-344264060b99/
        # wsman-xpress-remote-shell-compression?forum=os_windowsprotocols

        # headers.update({'rsp:CompressionType': {'@soap:mustUnderstand': 'true', '#text': 'xpress'}})
        # only include the operation timeout if the user specified one when the class was instantiated
        # or if the user explicitly set one when invoking a method.
        if operation_timeout is not None:
            headers.update(self._build_operation_timeout(operation_timeout))
        elif self.default_operation_timeout is not None:
            headers.update(self.default_operation_timeout)

        headers.update(self._build_selectors(resource.selectors))
        headers.update(self._build_options(resource.options))
        headers.update(self._build_max_envelope(max_envelope_size))
        headers.update(self._build_locale(locale))
        return headers

Session.MaxEnvelopeSize = 153600
Session.Locale = 'en-US'

Session.Address = {'a:Address': {
    '@mustUnderstand': 'true',
    '#text': 'http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous'
}}
# Static members that can be safely shared with all instances
Session.WSManNamespace = '{http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd}'
Session.AddressingNamespace = '{http://schemas.xmlsoap.org/ws/2004/08/addressing}'
Session.SoapContentType = {'Content-Type': 'application/soap+xml; charset=utf-8'}

# WSMan SOAP Actions
Session.GetAction = 'http://schemas.xmlsoap.org/ws/2004/09/transfer/Get'
Session.PutAction = 'http://schemas.xmlsoap.org/ws/2004/09/transfer/Put'
Session.DeleteAction = 'http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete'
Session.CreateAction = 'http://schemas.xmlsoap.org/ws/2004/09/transfer/Create'
Session.CommandAction = 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command'
Session.ReceiveAction = 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive'
