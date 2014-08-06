from api.resourcelocator import ResourceLocator
from api.session import Session


class WinRmClient(object):
    """
    Factory object for building sessions and connection options
    """
    def create_session(self):
        """
        Returns a WinRM Session
        """

        session = Session('https://bp1lcsap019:5986/wsman', 'ian.clegg@uk.bp.com', 'password')
        resource = ResourceLocator('http://schemas.microsoft.com/wbem/wsman/1/wmi/root/cimv2/Win32_logicaldisk')
        resource.add_selector('DeviceId', 'c:')

        response = session.get(resource)
        return response
