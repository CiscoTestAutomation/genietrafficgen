
import logging
from ixnetwork_restpy import SessionAssistant
from genie.trafficgen.trafficgen import TrafficGen

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

        self.rest_server_ip = str(connection_args.get('ip', ''))
        self.port = connection_args.get('port')
        self.session_id = connection_args.get('session_id')
        self.chassis_ip = connection_args.get('chassis_ip')
        self.log_level = connection_args.get('log_level', 'info')
        self.logfile = connection_args.get('logfile')
        self.clear_config = connection_args.get('clear_config', False)
        self.chain_topology = connection_args.get('chain_topology')
        self.master_chassis = connection_args.get('master_chassis')
        self.sequence_id = connection_args.get('sequence_id')
        self.cable_length = connection_args.get('cable_length')

    def connect(self):
        logger.info(f'Connecting to IxNetwork API via {self.rest_server_ip}:{self.port}')
        self.session = SessionAssistant(IpAddress=self.rest_server_ip, RestPort=self.port,
                                        UserName=self.username, Password=self.password,
                                        SessionName=None, SessionId=self.session_id, ApiKey=None,
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
            if chassisStatus.State != 'ready':
                raise Exception('Chassis not in ready state, found state {}'.format(chassisStatus.State))

    @property
    def connected(self):
        if hasattr(self, 'session'):
            session = self.session.Session.find()
            if session.State == 'ACTIVE':
                return True
        return False
