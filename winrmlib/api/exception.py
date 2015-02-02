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

class WSManException(Exception):
    """
    Exception raised by failures in SSH2 protocol negotiation or logic errors.
    """
    pass

class AuthenticationException(Exception):
    """
    Exception raised by failures in SSH2 protocol negotiation or logic errors.
    """
    pass


class FaultException(Exception):
    """
    Exception raised by failures in SSH2 protocol negotiation or logic errors.
    """
    pass