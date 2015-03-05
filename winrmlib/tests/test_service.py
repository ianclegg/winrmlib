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
import os
import mock
import unittest
import responses

import sys
sys.path.append("../")

from api.service import Service
from api.exception import WSManException
from api.exception import WSManOperationException
from api.exception import WSManAuthenticationException

class ServiceParseCase(unittest.TestCase):

    class Response(object):
        def __init__(self):
            self.empty_response = self._load_test_asset('empty_response')
            self.command_response = self._load_test_asset('command_response')
            self.operation_timeout = self._load_test_asset('operation_timeout')
            self.challenge_encrypt = ''

        def _load_test_asset(self, name):
            filename = os.path.join(os.path.dirname(__file__), 'assets', name)
            with open(filename + '.xml', 'r') as asset_file:
                return asset_file.read()

    @mock.patch('requests.Session.post')
    def test_headers_namespaces_are_translated_to_xml(self, mock_post):
        """
        The service should translate a dictionary to xml, this is a casual test because the logic is mostly
        implemented in xmltodict
        """
        headers = {'a': 'test', 'b': 'test', 'n': 'test', 'x': 'test', 'w': 'test'}
        mock_response = mock.Mock()
        mock_response.status_code = 200
        mock_response.content = self.response.command_response
        mock_post.return_value = mock_response

        service = Service('http://server:5985', 'username', 'password', False)
        service.invoke(headers, {})

        args, kwargs = mock_post.call_args
        self.assertTrue(u'<a>test</a>' in kwargs['data'])
        self.assertTrue(u'<b>test</b>' in kwargs['data'])
        self.assertTrue(u'<n>test</n>' in kwargs['data'])
        self.assertTrue(u'<x>test</x>' in kwargs['data'])
        self.assertTrue(u'<w>test</w>' in kwargs['data'])


    @responses.activate
    def test_200_with_empty_body_raises_exception(self):
        """
        Ensure a 200 response without a soap body is handled
        """
        responses.add(responses.POST, 'http://server:5985',
                      body=self.response.empty_response,
                      status=200, content_type='application/soap+xml')

        service = Service('http://server:5985', 'username', 'password', False)

        with self.assertRaises(WSManException) as context:
            service.invoke('headers', 'body')
        self.assertEqual('the remote host returned an empty soap response', context.exception.message)

    @responses.activate
    def test_200_with_invalid_body_raises_exception(self):
        """
        Ensure a 200 response with an empty or non-xml response is handled
        """
        responses.add(responses.POST, 'http://server:5985',
                      body='invalid_xml_response',
                      status=200, content_type='application/soap+xml')

        service = Service('http://server:5985', 'username', 'password', False)

        with self.assertRaises(WSManException) as context:
            service.invoke('headers', 'body')
        self.assertEqual('the remote host returned an invalid soap response', context.exception.message)

    @responses.activate
    def test_200_soap_fault_to_exception_translation(self):
        """
        SOAP Faults should be translated to WSManOperationException's
        """
        responses.add(responses.POST, 'http://server:5985',
                      body=self.response.operation_timeout,
                      status=200, content_type='application/soap+xml')

        service = Service('http://server:5985', 'username', 'password', False)

        with self.assertRaises(WSManOperationException) as context:
            service.invoke('headers', 'body')
        error = 'The WS-Management service cannot complete the operation within the time specified in OperationTimeout.'
        self.assertRegexpMatches(context.exception.message, error)

    @responses.activate
    def test_302_raises_exception(self):
        """
        We should not follow HTTP 302 redirects
        """
        response_headers = {'ContentLength': '0'}
        responses.add(responses.POST, 'http://server:5985',
                      adding_headers=response_headers,
                      status=302)

        service = Service('http://server:5985', 'username', 'password', False)
        with self.assertRaises(WSManException) as context:
            service.invoke('headers', 'body')
        self.assertEqual(context.exception.message, 'the remote host returned an unexpected http status code')

    @responses.activate
    def test_401_no_body_exception_translation(self):
        """
        If authentication fails a 401 is returned to requests, this should be handled
        :return:
        """
        response_headers = {'ContentLength': '0'}
        responses.add(responses.POST, 'http://server:5985',
                      adding_headers=response_headers,
                      status=401)

        service = Service('http://server:5985', 'username', 'password', False)
        with self.assertRaises(WSManAuthenticationException) as context:
            service.invoke('headers', 'body')
        self.assertEqual(context.exception.message, 'the remote host rejected authentication')

    @responses.activate
    def test_500_raises_exception(self):
        """
        If the server fails or cannot continue it may return a 500, ensure this is handled
        :return:
        """
        response_headers = {'ContentLength': '0'}
        responses.add(responses.POST, 'http://server:5985',
                      adding_headers=response_headers,
                      status=500)
        service = Service('http://server:5985', 'username', 'password', False)
        with self.assertRaises(WSManException) as context:
            service.invoke('headers', 'body')
        self.assertEqual(context.exception.message, 'the remote host returned an unexpected http status code')

    response = Response()

if __name__ == '__main__':
    unittest.main()
