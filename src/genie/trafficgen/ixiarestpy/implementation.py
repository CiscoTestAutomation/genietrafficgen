import re
import logging
from ixnetwork_restpy import SessionAssistant
from genie.trafficgen.trafficgen import TrafficGen

# used to create a unique session name
import uuid
from genie.utils.timeout import Timeout

from pyats.utils.secret_strings import SecretString, to_plaintext
from pyats.connections.utils import set_hltapi_environment_variables

logger = logging.getLogger(__name__)


class IxiaRestPy(TrafficGen):

    def __init__(self, *args, **kwargs):

        super().__init__(*args, **kwargs)

        self.device = self.device or kwargs.get('device')
        self.via = kwargs.get('via', 'tgn')

        if self.device is not None:
            connection_args = self.device.connections.get(self.via)
        else:
            connection_args = kwargs

        creds = self.device.credentials
        self.username = creds.get('default', {}).get('username', 'admin')
        self.password = creds.get('default', {}).get('password', 'admin')
        if isinstance(self.password, SecretString):
            self.password = to_plaintext(self.password)

        self.rest_server_ip = str(connection_args.get('ip', ''))
        self.port = connection_args.get('port')
        self.session_id = connection_args.get('session_id')
        self.session_name = str(uuid.uuid4())
        self.chassis_ip = connection_args.get('chassis_ip')
        self.log_level = connection_args.get('log_level', 'info')
        self.logfile = connection_args.get('logfile')
        self.clear_config = connection_args.get('clear_config', False)
        self.chain_topology = connection_args.get('chain_topology')
        self.master_chassis = connection_args.get('master_chassis')
        self.sequence_id = connection_args.get('sequence_id')
        self.cable_length = connection_args.get('cable_length')

        # Set environment variables for IXIA connection
        ixnetwork_version = self.connection_info.get('ixnetwork_version')
        if ixnetwork_version:
            set_hltapi_environment_variables(ixnetwork_version)
        else:
            logger.warning(f'ixnetwork_version not defined for device '
                           f'{str(self.device)} via {self.via}')

    def connect(self):
        logger.info(f'Connecting to IxNetwork API via {self.rest_server_ip}:{self.port}')
        self.session = SessionAssistant(IpAddress=self.rest_server_ip, RestPort=self.port,
                                        UserName=self.username, Password=self.password,
                                        SessionName=self.session_name, SessionId=self.session_id, ApiKey=None,
                                        ClearConfig=self.clear_config, LogLevel=self.log_level,
                                        LogFilename=self.logfile)
        self.ixnetwork = self.session.Ixnetwork
        self.requests_session = self.ixnetwork._connection._session

        # Connect to chassis
        if self.chassis_ip is not None:
            chassisStatus = self.ixnetwork.AvailableHardware.Chassis.add(Hostname=self.chassis_ip,
                                                                         ChainTopology=self.chain_topology,
                                                                         MasterChassis=self.master_chassis,
                                                                         SequenceId=self.sequence_id,
                                                                         CableLength=self.cable_length)

        # Wait until chassis is ready
        timeout = Timeout(max_time = 30, interval = 5, disable_log = False)
        while timeout.iterate():

            chassisStatus = self.ixnetwork.AvailableHardware.Chassis.find(Hostname=self.chassis_ip)

            logger.info(f'Chassis state: {chassisStatus.State}')
            if chassisStatus.State == 'ready':
                return
            timeout.sleep()

        else:
            if chassisStatus.State != 'ready':
                raise Exception('Chassis not in ready state, found state {}'.format(chassisStatus.State))

    @property
    def connected(self):
        if hasattr(self, 'session'):

            # The below is added to get the active session in case of multi chassis support.
            # SessionName also can be used to find the active session from the list of sessions
            # available but currently ixnetwork doesn't support it.

            # This gives us the active session hrefs
            # links = ['/api/v1/sessions/8020/ixnetwork/globals']
            response = self.ixnetwork._connection._read(
            "%s/ixnetwork/globals?includes=buildNumber,username" % self.session.Session.href
            )
            links = [link.get('href') for link in response.get('links')]

            if links:
                # This regex gives us the 'id' from the hrefs that we got from response
                # user_id = '8020'
                re_link = re.match(r"^.*\/(?P<ID>[0-9]+)\/.*$", links[0])

                try:
                    user_id = re_link.groupdict()["ID"]
                except:
                    logger.error("Could not find the valid session.")
                    return False

                # If the SessionName is supported the code will be lot simpler by leveraging
                # the find api like below
                # session = self.session.Session.find(Name=self.session_name)

                sessions = self.session.Session.find()
                logger.info(f'Session information : {sessions}')

                # The loops through all the sessions and identifies the state based on it
                # The information would look like below,
                # Session information :
                #     Sessions[0]: /api/v1/sessions/8020
                #     ApplicationType: ixnrest
                #     Id: 8020
                #     Name:
                #     State: ACTIVE
                #     UserId: cmgruser0-8020
                #     UserName: cmgruser0

                for session in sessions:
                    if str(session.Id) == user_id:
                        self.session_id = session.Id
                        logger.info(f'Session state information : {session.State}')

                        if session.State == 'ACTIVE':
                            return True
        return False    
    
    def disconnect(self):
        if self.session_id:
            self.session.Session.find(Id=self.session_id)[0].remove()
            logger.info(f"The session {self.session_id} is removed successfully.")
