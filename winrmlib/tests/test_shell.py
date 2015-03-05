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

import mock
import unittest

import sys
sys.path.append("../")

from shell import CommandShell


class ShellOpenCase(unittest.TestCase):
    """
    Test cases covering the Shell.open() method
    """

    @mock.patch('shell.Session')
    def test_should_open_set_shell_id(self, mock_session):
        expected_id = '0000'
        mock_instance = mock_session.return_value
        mock_instance.create.return_value = {'rsp:Shell': {'rsp:ShellId': expected_id}}
        mock_instance.command.return_value = {'rsp:CommandResponse': {'rsp:CommandId': '9999'}}

        shell = CommandShell('http://server:5985', 'username', 'password')
        shell.open()
        shell.run('unittest')

        args, kwargs = mock_instance.command.call_args
        self.assertEqual(expected_id, args[0].selectors['ShellId'])


class ShellRunCase(unittest.TestCase):
    """
    Test cases covering the Shell.open() method
    """

    @mock.patch('shell.Session')
    def test_should_open_set_shell_id(self, mock_session):
        mock_instance = mock_session.return_value
        mock_instance.create.return_value = {'rsp:CommandResponse': {'rsp:CommandId': '123'}}
        mock_instance.command.return_value = {'rsp:CommandResponse': {'rsp:CommandId': '9999'}}
        shell = CommandShell('http://server:5985', 'username', 'password')
        shell.__shell_id = 123
        shell.open()
        shell.run('')

        self.assertEqual('123', '123')

class ShellReceiveCase(unittest.TestCase):
    """
    Test cases covering the Shell.open() method
    """

    @mock.patch('shell.Session')
    def test_should_receive(self, mock_session):
        pass


if __name__ == '__main__':
    unittest.main()
