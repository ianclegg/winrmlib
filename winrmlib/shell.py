import base64
from api.resourcelocator import ResourceLocator
from api.session import Session
from suds.sax.element import Attribute
from suds.sax.element import Element


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
        self.session = Session(endpoint, 'krb5', username, password)
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
        shell = Element('Shell', ns=CommandShell.ShellNamespace)
        shell.append(CommandShell.InputStreams).setText(" ".join(input_streams))
        shell.append(CommandShell.OutputStreams).setText(" ".join(output_streams))
        shell.append(Element('IdleTimeout', ns=CommandShell.ShellNamespace).setText(self.idle_timeout))
        if self.working_directory is not None:
            shell.append(Element('WorkingDirectory'), ns=CommandShell.ShellNamespace).setText(self.working_directory)
        if self.environment is not None:
            shell.append(CommandShell._build_environment())

        response = self.session.create(self.resource, shell)
        self.shellId = response.ReferenceParameters.SelectorSet.Selector.value

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
        resource = ResourceLocator(CommandShell.ShellResource)
        resource.add_selector('ShellId', self.shellId)
        resource.add_option('WINRS_SKIP_CMD_SHELL', ['TRUE', 'FALSE'][bool(skip_cmd_shell)], True)
        resource.add_option('WINRS_CONSOLEMODE_STDIN', ['TRUE', 'FALSE'][bool(console_mode_stdin)], True)

        commandline = Element('CommandLine', ns=CommandShell.ShellNamespace)
        commandline.append(Element('Command', ns=CommandShell.ShellNamespace).setText(command))

        for argument in arguments:
            commandline.append(Element('Arguments', ns=CommandShell.ShellNamespace).setText(argument))

        response = self.session.command(resource, commandline)
        return response.CommandId

    def receive(self, command_id, streams=('stdout', 'stderr')):
        (session_streams, exit_code, done) = self._receive_once(command_id, streams)
        complete_streams = session_streams
        while not done:
            (session_streams, exit_code, done) = self._receive_once(command_id, streams)
            for stream_name in session_streams:
                complete_streams[stream_name] += session_streams[stream_name]

        if sorted(complete_streams.keys()) == sorted(['stderr', 'stdout']):
            return complete_streams['stdout'], complete_streams['stderr'], exit_code
        else:
            return complete_streams, exit_code

    def _receive_once(self, command_id, streams=('stdout', 'stderr')):
        resource = ResourceLocator(CommandShell.ShellResource)
        resource.add_selector('ShellId', self.shellId)
        stream_element = Element('DesiredStream', ns=CommandShell.ShellNamespace).setText(" ".join(streams))
        stream_element.attributes.append(Attribute("CommandId", command_id))
        receive = Element('Receive', ns=CommandShell.ShellNamespace)
        receive.append(stream_element)
        response = self.session.recieve(resource, receive)

        decoded_streams = {}
        for stream in streams:
            decoded_streams[stream] = ''

        for stream in response.Stream:
            if stream._CommandId == command_id and hasattr(stream, 'value'):
                decoded_streams[stream._Name] += base64.b64decode(stream.value)

        exit_code = None
        done = response.CommandState._State == CommandShell.StateDone
        if done:
            exit_code = response.CommandState.ExitCode

        return decoded_streams, exit_code, done

    def close(self):
        resource = ResourceLocator(CommandShell.ShellResource)
        resource.add_selector('ShellId', self.shellId)
        self.session.delete(resource)

    @staticmethod
    def _build_environment(environment):
        variables = Element('Environment', ns=CommandShell.ShellNamespace)
        for key, value in environment.items():
            variable = Element('Variable', ns=CommandShell.ShellNamespace).setText(value)
            variable.attributes.append(Attribute("Name", key))
            variables.append(variable)
        return variables

# Namespaces
CommandShell.ShellResource = 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd'
CommandShell.ShellNamespace = ('rsp', 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell')
CommandShell.InputStreams = Element('InputStreams', ns=CommandShell.ShellNamespace)
CommandShell.OutputStreams = Element('OutputStreams', ns=CommandShell.ShellNamespace)
CommandShell.Environment = Element('Environment', ns=CommandShell.ShellNamespace)

# Command States
CommandShell.StateDone = 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done'
CommandShell.StatePending = 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Pending'
CommandShell.StateRunning = 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Running'
