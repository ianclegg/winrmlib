from api.resourcelocator import ResourceLocator
from api.session import Session
from shell import CommandShell


class WinRmClient(object):
    """
    Factory object for building sessions and connection options
    """
    @staticmethod
    def create_session():
        """
        Returns a WinRM Session
        """
        shell = CommandShell('https://sever', 'user@realm', 'password')
        shell.open()
        command_id = shell.run('c:\Windows\System32\ipconfig.exe', ['/all'])
        (stdout, stderr, exit_code) = shell.receive(command_id)
        print stdout
        shell.close()

        return None

if __name__ == '__main__':
    WinRmClient.create_session()
