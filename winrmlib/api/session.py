import os
import uuid
import urllib2

from resourcelocator import ResourceLocator

from suds.bindings import binding
from suds.client import Client
from suds.sax.element import Element
from suds.sax.attribute import Attribute
from suds.transport.https import HttpAuthenticated
from suds.transport.https import WindowsHttpAuthenticated

from kerberoshandler import KerberosHttpAuthenticated

class Session(object):
    """
    Factory object for building sessions and connection options
    """

    def __init__(self, endpoint, auth, username, password):
        transport = Session._build_transport(endpoint, auth, username, password)
        wsdl_file = os.path.join(os.path.dirname(__file__), 'assets', 'winrm.wsdl')
        self.endpoint = endpoint
        self.To = Element('To', ns=Session.AddressingNamespace).setText(endpoint)
        self.client = Client("file://%s" % wsdl_file.replace('\\', '/'), location=endpoint, transport=transport,
                             prettyxml=True)
        # plugins=[RemoveEmptyElementsPlugin()])
        self.client.set_options(headers=Session.SoapContentType)

    def get(self, resource):
        """
        resource can be a URL or a ResourceLocator
        """
        if isinstance(resource, str):
            resource = ResourceLocator(resource)

        headers = self._build_headers(resource, Session.GetAction)
        self.client.set_options(tsoapheaders=headers)
        return self.client.service.Get()

    def put(self, resource, obj):
        """
        resource can be a URL or a ResourceLocator
        """
        pass

    def delete(self, resource):
        """
        resource can be a URL or a ResourceLocator
        """
        if isinstance(resource, str):
            resource = ResourceLocator(resource)

        headers = self._build_headers(resource, Session.DeleteAction)
        self.client.set_options(soapheaders=headers)
        return self.client.service.Delete()

    def create(self, resource, obj):
        """
        resource can be a URL or a ResourceLocator
        """
        if isinstance(resource, str):
            resource = ResourceLocator(resource)

        headers = self._build_headers(resource, Session.CreateAction)
        self.client.set_options(soapheaders=headers)
        return self.client.service.Create(obj)

    def command(self, resource, obj):
        """
        resource can be a URL or a ResourceLocator
        """
        if isinstance(resource, str):
            resource = ResourceLocator(resource)

        headers = self._build_headers(resource, Session.CommandAction)
        self.client.set_options(soapheaders=headers)
        return self.client.service.Command(obj)

    def recieve(self, resource, obj):
        """
        resource can be a URL or a ResourceLocator
        """
        if isinstance(resource, str):
            resource = ResourceLocator(resource)

        headers = self._build_headers(resource, Session.ReceiveAction)
        self.client.set_options(soapheaders=headers)
        return self.client.service.Command(obj)

    @staticmethod
    def _build_transport(endpoint, auth, username, password):
        # Provide credentials to the transport
        if auth == 'krb5':
            transport = KerberosHttpAuthenticated()
        elif auth == 'ntlm':
            transport = WindowsHttpAuthenticated()
        elif auth == 'basic':
            transport = HttpAuthenticated()

        # Provide credentials to the transport
        password_mgr = urllib2.HTTPPasswordMgrWithDefaultRealm()
        password_mgr.add_password(None, endpoint, username, password)
        transport.pm = password_mgr
        return transport

    @staticmethod
    def _build_selectors(selectors):
        # Build the WSMan SelectorSet Element from the selector dictionary
        selector_set = Element('SelectorSet', ns=Session.WSManNamespace)
        for selector_name in selectors.iterkeys():
            selector_value = selectors[selector_name]

            selector = Element('Selector', ns=Session.WSManNamespace).setText(selector_value)
            selector_name_attribute = Attribute("Name", selector_name)
            selector.attributes.append(selector_name_attribute)

            # Add the selector to the SelectorSet
            selector_set.append(selector)
        return selector_set

    @staticmethod
    def _build_options(options):
        option_set = Element('OptionSet', ns=Session.WSManNamespace)
        for name, (value, must_comply) in options.iteritems():
            must_comply = bool(must_comply)
            # TODO add mustcomply attribute to element
            option = Element('Option', ns=Session.WSManNamespace).setText(value)
            option_name_attribute = Attribute("Name", name)
            option.attributes.append(option_name_attribute)

            option_set.append(option)
        return option_set

    def _build_headers(self, resource, action):
        # Each request should have a unique Message ID
        selectors = Session._build_selectors(resource.selectors)
        options = Session._build_options(resource.options)
        resource = Element('ResourceURI', ns=Session.WSManNamespace).setText(resource.url)

        message_id = Element('MessageID', ns=Session.AddressingNamespace)
        message_id.setText(format(uuid.uuid4()))
        action_id = Element('Action', ns=Session.AddressingNamespace)
        action_id.setText(action)

        return [self.To, Session.ReplyTo,
                message_id, action_id, resource,
                selectors, options,
                Session.Locale, Session.MaxEnvelope]

# There does not appear to be a better alternative to getting a SOAP 1.2 header
# This is a global solution to a local problem, and may cause issues with other suds users
binding.envns=('SOAP-ENV', 'http://www.w3.org/2003/05/soap-envelope')

# Static members that can be safely shared with all instances
Session.WSManNamespace = ('w', 'http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd')
Session.MaxEnvelope = Element('MaxEnvelopeSize', ns=Session.WSManNamespace).setText('153600')
Session.Locale = Element('Locale').attributes.append(Attribute("xml:lang", "en-US"))
Session.AddressingNamespace = ('a', 'http://schemas.xmlsoap.org/ws/2004/08/addressing')
Session.Action = Element('Action', ns=Session.AddressingNamespace)
Session.ReplyTo = Element('ReplyTo', ns=Session.AddressingNamespace)
Session.Address = Element('Address', ns=Session.AddressingNamespace)\
    .setText('http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous')
Session.ReplyTo.append(Session.Address)
Session.SoapContentType = {'Content-Type': 'application/soap+xml; charset=utf-8'}

# WSMan SOAP Actions
Session.GetAction = 'http://schemas.xmlsoap.org/ws/2004/09/transfer/Get'
Session.PutAction = 'http://schemas.xmlsoap.org/ws/2004/09/transfer/Put'
Session.DeleteAction = 'http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete'
Session.CreateAction = 'http://schemas.xmlsoap.org/ws/2004/09/transfer/Create'
Session.CommandAction = 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command'
Session.ReceiveAction = 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive'
