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

import xmltodict
from collections import OrderedDict
from requests import Session
from exception import WSManException
from exception import AuthenticationException
from authentication import HttpCredSSPAuth
from authentication import HttpNtlmAuth


class Service(object):
    """
    SOAP Service
    """

    def __init__(self, endpoint, auth, username, password, delegation=False, **kwargs):
        """
        # Kerberos authentication does not require a password if the MIT kerberos GSS-API mechanism already has a
        # valid service ticket for the WSMAN service on the target server. However if the callee wishes to use
        # credential delegation with Kerberos they must still provide a password (see Microsoft [MS-CSSP] Protocol)
        #
        # Credential delegation requires an authentication mechanism which provide message integrity and confidentiality
        # such as NTLM or Kerberos; basic authentication cannot be used.
        #
        # Kerberos requires the username in UPN (RFC xxxx) form. UPN or NetBIOS usernames can be used whith NTLM
        """
        self.session = Session()
        self.endpoint = endpoint

        if not auth in Service.Avaliable_Mechanisms:
            raise WSManException("The following authentication mechanisms are supported 'basic', 'ntlm' or 'kerberos'")

        if delegation:
            if auth == 'basic':
                raise WSManException('Credential Delegation (CredSSP) requires NTLM or Kerberos authentication')
            self.session.auth = HttpCredSSPAuth(username, password)
        elif auth == 'krb5':
            self.session.auth = HttpCredSSPAuth(username, password) #, self.session)
        elif auth == 'ntlm':
            self.session.auth = HttpNtlmAuth("SERVER2012", username, password, self.session)

    def invoke(self, headers, body):
        """
        Invokes the soap service
        """
        xml = Service._create_request(headers, body)
      #  try:
        response = self.session.post(self.endpoint, verify=False, data=xml)
    #    except Exception, e:
         #   b =e
      #      pass
      #  print response.content

        if response.status_code == 200:
            return Service._parse_response(response.content)

        if 500 < response.status_code >= 400:
            if response.status_code == 401:
                # auth denied
                raise AuthenticationException("")
            else:
                # another 40x
                raise AuthenticationException("")
        else:
            Service._parse_response(response.content)

    @staticmethod
    def _create_request(headers, body):
        """
        Create the SOAP 1.2 Envelope
        An ordered dictionary is required to ensure the same order is reflected in the XML, otherwise the
        SOAP Body element would appear before the Header element.
        """
        envelope = OrderedDict()
        for (namespace, alias) in Service.Namespaces.iteritems():
            envelope['@xmlns:' + alias] = namespace
        envelope['soap:Header'] = headers
        envelope['soap:Body'] = body
        return xmltodict.unparse({'soap:Envelope': envelope}, encoding='utf-8')

    @staticmethod
    def _parse_response(xml):
        """
        Attempt to parse the SOAP response and return a python object
        Raise a WSManException if a Fault is found
        """
        try:
            soap_response = xmltodict.parse(xml, process_namespaces=True, namespaces=Service.Namespaces)
            body = soap_response['soap:Envelope']['soap:Body']
            if body is not None and 'Fault' in body:
                raise WSManException("SOAP Fault")
            return body
        except Exception, e:
            b =e
            raise WSManException("Invalid Soap Response")

Service.Avaliable_Mechanisms = ["basic", "ntlm", "kerberos"]
Service.Namespaces = {
    'http://www.w3.org/2003/05/soap-envelope': 'soap',
    'http://schemas.xmlsoap.org/ws/2004/08/addressing': 'a',
    'http://schemas.dmtf.org/wbem/wsman/1/cimbinding.xsd': 'b',
    'http://schemas.xmlsoap.org/ws/2004/09/enumeration': 'n',
    'http://schemas.xmlsoap.org/ws/2004/09/transfer': 'x',
    'http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd': 'w',
    'http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd': 'p',
    'http://schemas.microsoft.com/wbem/wsman/1/windows/shell': 'rsp',
    'http://schemas.microsoft.com/wbem/wsman/1/config': 'cfg'
}
