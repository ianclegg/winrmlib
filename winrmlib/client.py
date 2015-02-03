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

from shell import CommandShell

class WinRmClient(object):
    """
    Factory object for building sessions and connection options
    """
    @staticmethod
    def create_session():
        """
        shell = CommandShell('http://192.168.145.132:5985/wsman', 'Administrator', 'Pa55w0rd')
        """
        shell = CommandShell('http://192.168.137.154:5985/wsman', 'Administrator', 'Pa55w0rd')
        shell.open()
        command_id = shell.run('ipconfig', ['/all'])
        (stdout, stderr, exit_code) = shell.receive(command_id)
        print stdout
        shell.close()

        return None
if __name__ == '__main__':
    WinRmClient.create_session()
