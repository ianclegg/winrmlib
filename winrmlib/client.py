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

import sys
import logging
from logging.config import dictConfig

# configure a logger to get some insight on what ntlmlib does
logging_config = dict(
{
    'version': 1,
    'formatters': {
        'standard': {
            'format': '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
        },
    },
    'handlers': {
        'default': {
            'level': 'ERROR',
            'class': 'logging.StreamHandler',
        },
    },
    'loggers': {
        '': {
            'handlers': ['default'],
            'level': 'ERROR',
            'propagate': True
        }
    }
})
dictConfig(logging_config)
logger = logging.getLogger()

from winrmlib.shell import CommandShell

class WinRmClient(object):
    """
    Factory object for building sessions and connection options
    """
    @staticmethod
    def create_session():
        """
        shell = CommandShell('http://192.168.145.132:5985/wsman', 'Administrator', 'Pa55w0rd')
        """
        shell = CommandShell('http://192.168.137.238:5985/wsman', 'Administrator', 'Pa55w0rd')
        shell.open()
        command_id = shell.run('ipconfig', ['/all'])
        (stdout, stderr, exit_code) = shell.receive(command_id)
        sys.stdout.write(stdout.strip() + '\r\n')
        shell.close()

        return None

if __name__ == '__main__':
    for x in range(0, 1):
        WinRmClient.create_session()
