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

import base64
import logging

from winrmlib.api.session import Session
from winrmlib.api.resourcelocator import ResourceLocator
from winrmlib.api.exception import WSManOperationException

try:
    from collections import OrderedDict
except ImportError:
    from ordereddict import OrderedDict

logger = logging.getLogger(__name__)


class CommandShell(object):

    def __init__(self, endpoint, username, password, **kwargs):
        """
        timeout
        codepage
        noprofile
        environment
        """
        # Process arguments
        self.environment = kwargs.get('environment', None)
        self.working_directory = kwargs.get('working_directory', None)
        self.idle_timeout = kwargs.get('idle_timeout', 180000)
        codepage = kwargs.get('codepage', 437)

        # Build the Session and the SOAP Headers
        self.__shell_id = None
        self.session = Session(endpoint, username, password)
        self.resource = ResourceLocator(CommandShell.ShellResource)
        self.resource.add_option('WINRS_CODEPAGE', codepage, True)
        if bool(kwargs.get('noprofile', False)):
            self.resource.add_option('WINRS_NOPROFILE', 'FALSE', True)
        else:
            self.resource.add_option('WINRS_NOPROFILE', 'TRUE', True)

    def open(self, input_streams=['stdin'], output_streams=['stderr', 'stdout']):
        """
        Opens the remote shell
        """
        shell = dict()
        shell['rsp:InputStreams'] = " ".join(input_streams)
        shell['rsp:OutputStreams'] = " ".join(output_streams)
        shell['rsp:IdleTimeout'] = str(self.idle_timeout)

        if self.working_directory is not None:
            shell['rsp:WorkingDirectory'] = str(self.working_directory)

        if self.environment is not None:
            variables = []
            for key, value in self.environment.items():
                variables.append({'#text': str(value), '@Name': key})
            shell['rsp:Environment'] = {'Variable': variables}

        response = self.session.create(self.resource, {'rsp:Shell': shell})
        self.__shell_id = response['rsp:Shell']['rsp:ShellId']

    def run(self, command, arguments=(), console_mode_stdin=True, skip_cmd_shell=False):
        """This function does something.
        :param command: The command to be executed
        :type name: str.
        :param arguments: A list of arguments to be passed to the command
        :type state: str.
        :returns:  int -- the return code.
        :raises: AttributeError, KeyError

        iclegg: blocking i/o operations are slow, doesnt Python have a moden 'async' mechanism
        rather than replying on 80's style callbacks?
        """
        logging.info('running command: ' + command)
        resource = ResourceLocator(CommandShell.ShellResource)
        resource.add_selector('ShellId', self.__shell_id)
        resource.add_option('WINRS_SKIP_CMD_SHELL', ['FALSE', 'TRUE'][bool(skip_cmd_shell)], True)
        resource.add_option('WINRS_CONSOLEMODE_STDIN', ['FALSE', 'TRUE'][bool(console_mode_stdin)], True)

        command = OrderedDict([('rsp:Command', command)])
        command['rsp:Arguments'] = list(arguments)

        response = self.session.command(resource, {'rsp:CommandLine': command})
        command_id = response['rsp:CommandResponse']['rsp:CommandId']
        logging.info('receive command: ' + command_id)
        return command_id

    def receive(self, command_id, streams=('stdout', 'stderr'), command_timeout=60):
        """
        Recieves data
        :param command_id:
        :param streams:
        :param command_timeout:
        :return:
        """
        logging.info('receive command: ' + command_id)
        response_streams = dict.fromkeys(streams, '')
        (complete, exit_code) = self._receive_poll(command_id, response_streams)
        while not complete:
            (complete, exit_code) = self._receive_poll(command_id, response_streams)

        # This retains some compatibility with pywinrm
        if sorted(response_streams.keys()) == sorted(['stderr', 'stdout']):
            return response_streams['stdout'], response_streams['stderr'], exit_code
        else:
            return response_streams, exit_code

    def _receive_poll(self, command_id, response_streams):
        """
        Recieves data
        :param command_id:
        :param streams:
        :return:
        """
        logging.info('receive command: ' + command_id)
        resource = ResourceLocator(CommandShell.ShellResource)
        resource.add_selector('ShellId', self.__shell_id)

        stream_attributes = {'#text': " ".join(response_streams.keys()), '@CommandId': command_id}
        receive = {'rsp:Receive': {'rsp:DesiredStream': stream_attributes}}

        try:
            response = self.session.recieve(resource, receive)['rsp:ReceiveResponse']
        except Exception as e:
            return False, None

        # some responses will not include any output
        session_streams = response.get('rsp:Stream', ())
        if not isinstance(session_streams, list):
            session_streams = [session_streams]

        for stream in session_streams:
            if stream['@CommandId'] == command_id and '#text' in stream:
                response_streams[stream['@Name']] += base64.b64decode(stream['#text'])
                # XPRESS Compression Testing
                # print "\\x".join("{:02x}".format(ord(c)) for c in base64.b64decode(stream['#text']))
                # data = base64.b64decode(stream['#text'])
                # f = open('c:\\users\\developer\\temp\\data.bin', 'wb')
                # f.write(data)
                # f.close()
                # decode = api.compression.xpress_decode(data[4:])
        done = response['rsp:CommandState']['@State'] == CommandShell.StateDone
        if done:
            exit_code = int(response['rsp:CommandState']['rsp:ExitCode'])
        else: exit_code = None
        return done, exit_code

    def close(self):
        """
        Closes pipe
        :return:
        """
        resource = ResourceLocator(CommandShell.ShellResource)
        resource.add_selector('ShellId', self.__shell_id)
        self.session.delete(resource)


# Namespaces
CommandShell.ShellResource = 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd'

# Command States
CommandShell.StateDone = 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done'
CommandShell.StatePending = 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Pending'
CommandShell.StateRunning = 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Running'