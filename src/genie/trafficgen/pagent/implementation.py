# ---------------------------------------------------------------------------
# *             This code will only work internally within Cisco
# *              Any attempt to use it externally will fail and
# *                       no support will be provided
# ---------------------------------------------------------------------------

#
# pagent.py
#
# Copyright (c) 2021 by Cisco Systems, Inc.
# All rights reserved.
#
import time
import ipaddress
import logging

from .pagentflow import PG_Manager
from .pagentflow import PG_flow_igmpv2_report
from .pagentflow import PG_flow_igmpv3_report
from .pagentflow import PG_flow_igmp_leave

# Unicon
from unicon import Connection
from unicon.core.errors import (ConnectionValidationError,
                                ConnectionInfraError,
                                ConnectionError,
                                SpawnInitError,
                                SubCommandFailure)
# Genie
from genie.trafficgen.trafficgen import TrafficGen

# Logger
log = logging.getLogger(__name__)


class Pagent(TrafficGen):
    def __init__(self, *args, **kwargs):
        # Internal variables
        self.igmp_clients = {}
        self.client_seqnum = 1

        self.mcast_grps = {}
        self.mcast_srcs = {}

        super(Pagent, self).__init__(*args, **kwargs)
        self.device = self.device or kwargs.get('device')

        self.via = kwargs.get('via', 'tgn')

        if self.device is not None:
            connection_args = self.device.connections.get(self.via)
        else:
            connection_args = kwargs

        self.ip = connection_args.get('ip')
        self.port = connection_args.get('port')

        self.tg = None

    def connect(self):
        '''Connect to Pagent'''
        if self.tg and self.tg.connected:
            log.info('already connected')
            return

        if self.tg:
            self.tg.connect()
        else:
            try:
                self.tg = Connection(
                    hostname='traffic_gen',
                    start=['telnet {ip} {port}'.format(ip=self.ip,
                                                    port=self.port)],
                    os='ios', platform='pagent'
                )
                # Adding device cli attribute for backward compatibility for
                # test cases that use pagent with the traditional
                # execute/configure methods. This allows a pagent device to be
                # specified in the testbed using the genie.trafficgen.TrafficGen
                # class while also exposing some of the unicon methods to the
                # user
                self.device.cli = self.tg
                self.tg.connect()
            except (ConnectionValidationError, ConnectionInfraError,
                    ConnectionError, SpawnInitError, SubCommandFailure) as err:
                log.error('Failed to connect pagent: {e}'.format(e=str(err)))
                return

        self.pg = PG_Manager(self.tg)

    def disconnect(self):
        '''Disconnect from Pagent'''
        self.tg.disconnect()

    @property
    def connected(self):
        if self.tg:
            return self.tg.connected

        return False

    # Adding traditional CLI methods to allow user to use pagent with
    # traditional CLI user interface
    def configure(self, *args, **kwargs):
        return self.tg.configure(*args, **kwargs)

    def execute(self, *args, **kwargs):
        return self.tg.execute(*args, **kwargs)

    def sendline(self, *args, **kwargs):
        return self.tg.sendline(*args, **kwargs)

    def expect(self, *args, **kwargs):
        return self.tg.expect(*args, **kwargs)

    # Multicast APIs
    def create_multicast_group(self, groupip, inc_steps='0.0.0.0',
                               ip_prefix_len=32, group_nums=1):
        '''Create multicast group pool
           Args:
             groupip ('str'): group ipv4/ipv6 address
             inc_steps ('str'): Used to increment group address
             ip_prefix_len ('int'): Defaults to 32 for IPv4 and 128 for IPv6.
             group_nums ('int'): number of groups
           Returns:
             multicast group pool handler
           Raises:
             NotImplementedError
        '''
        grpkey = self._get_ippoolkey(groupip, inc_steps, group_nums)
        if grpkey in self.mcast_grps:
            log.warn('Multicast Group {} has been created'.format(groupip))
            return self.mcast_grps[grpkey]

        addr_max = self._get_ippoolmax(groupip, inc_steps, group_nums)
        self.mcast_grps[grpkey] = {
            'grp_ip': groupip,
            'steps': inc_steps,
            'pref_len': ip_prefix_len,
            'grp_num': group_nums,
            'grp_max': str(addr_max),
        }
        return grpkey

    def delete_multicast_group(self, group_handler):
        '''delete multicast group pool
           Args:
             group_handler ('obj'): multicast group pool handler
           Returns:
             True/False
           Raises:
             NotImplementedError
        '''
        grpkey = group_handler
        if grpkey in self.mcast_grps:
            del self.mcast_grps[grpkey]
            return True

        return False

    def create_multicast_source(self, sourceip, inc_steps='0.0.0.0',
                                ip_prefix_len=32, source_nums=1):
        '''Create multicast source pool
           Args:
             sourceip ('str'): source ipv4/ipv6 address
             inc_steps ('str'): Used to increment source address
             ip_prefix_len ('int'): Defaults to 32 for IPv4 and 128 for IPv6.
             source_nums ('int'): number of sources
           Returns:
             multicast source pool handler
           Raises:
             NotImplementedError
        '''
        srckey = self._get_ippoolkey(sourceip, inc_steps, source_nums)
        if srckey in self.mcast_srcs:
            log.warn('Multicast Source {} has been created'.format(sourceip))
            return srckey

        addr_max = self._get_ippoolmax(sourceip, inc_steps, source_nums)
        self.mcast_srcs[srckey] = {
            'src_ip': sourceip,
            'steps': inc_steps,
            'pref_len': ip_prefix_len,
            'src_num': source_nums,
            'src_max': str(addr_max),
        }
        return srckey

    def delete_multicast_source(self, source_handler):
        '''delete multicast source pool
           Args:
             source_handler ('obj'): multicast source pool handler
           Returns:
             True/False
           Raises:
             NotImplementedError
        '''
        srckey = source_handler
        if srckey in self.mcast_srcs:
            del self.mcast_srcs[srckey]
            return True

        return False

    # IGMP APIs
    def create_igmp_client(self, interface, clientip, version, vlanid=0):
        '''Create IGMP Client
           Args:
             interface ('str'): interface name
             clientip ('str'): ip address
             version ('int'): 2 or 3
             vlanid ('int'): vlan id
           Returns:
             igmp client handler
           Raises:
             NotImplementedError
        '''
        hkey = self._get_igmpclient_hkey(interface, vlanid, clientip)

        self._update_igmpclient_field(hkey, 'version', version)
        self._update_igmpclient_field(hkey, 'vlan', vlanid)

        return hkey

    def delete_igmp_client(self, client_handler):
        '''Delete IGMP Client
           Args:
             client_handler ('obj'): IGMP Client handler
           Returns:
             True/False
           Raises:
             NotImplementedError
        '''
        hkey = client_handler
        return self._del_igmpclient_hkey(hkey)

    def igmp_client_add_group(self, client_handler,
                              group_handler,
                              source_handler=None,
                              filter_mode='N/A'):
        '''IGMP Client add group membership
           Args:
             client_handler ('obj'): IGMP Client handler
             group_handler ('obj'):
                Multicast group pool handler created by create_multicast_group
             source_handler ('obj'):
                Multicast source handler created by create_multicast_source
                by default is None, means (*, g)
             filter_mode ('str'): include | exclude | N/A (by default)

             for v3 (*,g) which is (0.0.0.0, g)-exclude, the source_handler
             should be None, filter_mode should be exclude 
           Returns:
             group membership handler
           Raises:
             NotImplementedError
        '''

        hkey = client_handler
        gkey = group_handler
        skey = source_handler

        # generate group membership handler
        handle = "{client}:{grp}:{src}".format(client=hkey, grp=gkey,
                                               src=str(skey))

        grps = self._get_igmpclient_field(hkey, 'grps')
        grp_attr = self._get_igmpclient_field(hkey, 'grp_attr')
        if gkey not in grps:
            grps.append(gkey)
            grp_attr[gkey] = {}

        grp_attr[gkey][str(skey)] = {
            'fmode': filter_mode,
        }

        self._update_igmpclient_field(hkey, 'grps', grps)
        self._update_igmpclient_field(hkey, 'grp_attr', grp_attr)

        return handle

    def igmp_client_modify_group_filter_mode(self, client_handler,
                                             handler, filter_mode):
        '''IGMP Client modify group member filter mode, Only IGMP v3
           client is supported
           Args:
             client_handler ('obj'): IGMP Client handler
             handler ('obj'):
                Group membership handler created by igmp_client_add_group
             filter_mode: include | exclude
           Returns:
             Updated Group membership handler
           Raises:
             NotImplementedError
        '''
        hkey, gkey, skey = handler.split(':')
        if hkey != client_handler:
            log.error('Client handler and Membership handler mismatch')
            raise KeyError

        grps = self._get_igmpclient_field(hkey, 'grps')
        grp_attr = self._get_igmpclient_field(hkey, 'grp_attr')
        if gkey not in grps:
            log.error('Group not exist')
            raise KeyError

        version = self._get_igmpclient_field(hkey, 'version')
        if version != 3 or grp_attr[gkey][skey]['fmode'] == filter_mode:
            # Not supported operation
            log.error(
                'Not supported operation: change client {hkey} from '
                'version {ver} {fmode} mode to {upd_fmode}'.format(
                    hkey=hkey, ver=version,
                    fmode=grp_attr[gkey][skey]['fmode'],
                    upd_fmode=filter_mode,
                )
            )
            return

        # Modify the filter mode
        grp_attr[gkey][skey]['fmode'] = filter_mode
        self._update_igmpclient_field(hkey, 'grp_attr', grp_attr)

        interface, client_ip = hkey.split(',')
        vlan = self._get_igmpclient_field(hkey, 'vlan')

        # Pagent TGN does not support igmpv3 template
        # the implementation is actually a hack using igmpv1 format
        # it only supports one group record for now
        c_name = self._get_igmpclient_field(hkey, 'name')
        smac = self._tgn_client_mac_by_ip(client_ip)

        group = self.mcast_grps[gkey]['grp_ip']
        src_num = self.mcast_srcs[skey]['src_num']
        src_list = self._get_ippool_ips(self.mcast_srcs[skey]['src_ip'],
                                        self.mcast_srcs[skey]['steps'],
                                        src_num)

        if grp_attr[gkey][skey]['fmode'] == 'include':
            mode = 3
        else:
            mode = 4

        flow = PG_flow_igmpv3_report(c_name, smac, client_ip, group,
                                     src_num, src_list, mode, vlan)
        self.pg.send_traffic(flow, interface, 1)
        self.pg.clear_tgn()

        return handler

    def igmp_client_del_group(self, client_handler, handler):
        '''IGMP Client delete group membership
           Args:
             client_handler ('obj'): IGMP Client handler
             handler ('obj'):
                Group membership handler created by igmp_client_add_group
           Returns:
             True/False
           Raises:
             NotImplementedError/KeyError
        '''
        hkey, gkey, skey = handler.split(':')
        if hkey != client_handler:
            log.error('Client handler and Membership handler mismatch')
            raise KeyError

        # Remove the group from client
        grps = self._get_igmpclient_field(hkey, 'grps')
        grp_attr = self._get_igmpclient_field(hkey, 'grp_attr')
        if gkey not in grps:
            log.error('Group not exist')
            raise KeyError

        del grp_attr[gkey][skey]
        # If all source handler removed, then remove
        # then group handler membership as well
        if not grp_attr[gkey]:
            grps.remove(gkey)
            del grp_attr[gkey]

        self._update_igmpclient_field(hkey, 'grps', grps)
        self._update_igmpclient_field(hkey, 'grp_attr', grp_attr)

        return True

    def igmp_client_control(self, interface, client_handler, mode):
        '''IGMP Client protocol control
           Args:
             interface ('str'): interface name
             client_handler: IGMP Client handler
             mode ('mode'):
                start: start the client with sending igmp join message
                stop: stop the client with sending igmp leave message
                restart: restart the client
           Returns:
             True/False
           Raises:
             NotImplementedError
        '''
        hkey = client_handler

        if mode == 'start':
            self._start_igmpclient(hkey)

        elif mode == 'stop':
            self._stop_igmpclient(hkey)

        elif mode == 'restart':
            # Fake restart, simply re-sent join message.
            self._start_igmpclient(hkey)

        else:
            return False

        return True

    # ==============================================================
    # ip pool methods
    # ==============================================================
    def _get_ippoolkey(self, ip, steps, num):
        '''get the key of ip pool
           Args:
             ip ('str'): start ip address of the ip pool
             steps ('str'): increment step ip address of the ip pool
             num ('int'): address number of the ip pool
           Returns:
             the key of ip pool
           Raises:
             NotImplementedError
        '''
        return "{ip}_{steps}_{num}".format(ip=ip, steps=steps, num=num)

    def _get_ippoolmax(self, ip, steps, num):
        '''get the max address of the ip pool
           Args:
             ip ('str'): start ip address of the ip pool
             steps ('str'): increment step ip address of the ip pool
             num ('int'): address number of the ip pool
           Returns:
             the maximum address of ip pool
           Raises:
             NotImplementedError
        '''
        addr_ip = ipaddress.ip_address(ip)
        addr_inc = int(num) * int(ipaddress.ip_address(steps))
        addr_max = addr_ip + addr_inc
        return addr_max

    def _get_ippool_ips(self, ip, steps, num):
        '''get a list of ips of the ip pool
           Args:
             ip ('str'): start ip address of the ip pool
             steps ('str'): increment step ip address of the ip pool
             num ('int'): address number of the ip pool
           Returns:
             List of ips of ip pool
           Raises:
             NotImplementedError
        '''
        ip_start = ipaddress.ip_address(ip)
        ip_steps = ipaddress.ip_address(steps)
        ip_list = []
        # making src list
        for x in range(0, num):
            ip = ip_start + int(x) * int(ip_steps)
            ip_list.append(str(ip))

        return ip_list

    # =============================================================
    # IGMP Client management methods
    # Allocate a clientkey to track all the clients
    # This set of methods used to manage the igmp clients of pagent
    # ==============================================================

    def _get_igmpclient_hkey(self, interface, vlanid, clientip):
        '''Get host key of igmp client, create a new key for new client
           Args:
             interface ('str'): interface name
             vlanid ('int'): vlan id
             clientip ('str'): client ip address
           Returns:
             Host key of igmp client
           Raises:
             SubCommandFailure
        '''
        intf = interface

        # For Pagent, by default, vlan id is not supported in ICE
        # We need to create Ethernet subinterface for vlan encapsulation
        if intf not in self.igmp_clients:
            self.igmp_clients[intf] = {}
            try:
                # always no shutdown the main interface
                self.tg.configure(
                    [
                        'interface {intf}'.format(intf=interface),
                        'no shutdown',
                    ]
                )
            except SubCommandFailure:
                raise SubCommandFailure(
                    "Failed to no shutdown interface {intf}".format(
                        intf=interface
                    )
                )

        hkey = "{intf},{clientip}".format(intf=intf, clientip=clientip)
        if hkey not in self.igmp_clients[intf]:
            self.igmp_clients[intf][hkey] = {
                'name': 'c_{seq}'.format(seq=self.client_seqnum),
                # client state: idle | running
                # idle: client stopped/left
                # running: client running
                'state': 'idle',
                # group records
                'grps': [],
                'grp_attr': {},
            }
            self.client_seqnum = self.client_seqnum + 1
            log.info(
                'Client {hkey} created: {fields}'.format(
                    hkey=hkey,
                    fields=str(self.igmp_clients[intf][hkey])
                )
            )

        return hkey

    def _del_igmpclient_hkey(self, hkey):
        '''Delete a igmp client host key
           Args:
             hkey ('str'): igmp client host key
           Returns:
             True/False
           Raises:
             None
        '''
        intf, ip = hkey.split(',')
        if hkey in self.igmp_clients[intf]:
            del self.igmp_clients[intf][hkey]
            log.info(
                'Client {hkey} deleted'.format(
                    hkey=hkey
                )
            )
            return True

        return False

    def _update_igmpclient_field(self, hkey, key, value):
        '''Update igmpclient field by host key
           Args:
             hkey ('str'): igmp client host key
             key ('any'): field key
             value ('any'): field value
           Returns:
             None
           Raises:
             None
        '''
        intf, ip = hkey.split(',')
        self.igmp_clients[intf][hkey][key] = value
        log.info(
            'Client {hkey} update: {key}: {value}'.format(
                hkey=hkey, key=key, value=value
            )
        )

    def _get_igmpclient_field(self, hkey, key):
        '''Update igmpclient field by host key
           Args:
             hkey ('str'): igmp client host key
             key ('any'): field key
           Returns:
             field value
           Raises:
             KeyError
        '''
        intf, ip = hkey.split(',')
        if key == 'interface':
            return intf
        elif key == 'ip':
            return ip
        else:
            return self.igmp_clients[intf][hkey][key]

    def _start_igmpclient(self, hkey):
        '''Start a igmp client
           Args:
             hkey ('str'): host key of igmp client
           Returns:
             None
        '''
        version = self._get_igmpclient_field(hkey, 'version')
        grps = self._get_igmpclient_field(hkey, 'grps')
        grp_attr = self._get_igmpclient_field(hkey, 'grp_attr')

        if version == 2:
            for gkey in grps:
                self._tgn_send_igmpv2join(hkey, gkey)
        elif version == 3:
            for gkey in grps:
                for skey in grp_attr[gkey]:
                    self._tgn_send_igmpv3join(hkey, gkey, skey)
        self._update_igmpclient_field(hkey, 'state', 'running')

    def _stop_igmpclient(self, hkey):
        '''Stop a igmp client
           Args:
             hkey ('str'): host key of igmp client
           Returns:
             None
        '''
        version = self._get_igmpclient_field(hkey, 'version')
        grps = self._get_igmpclient_field(hkey, 'grps')
        grp_attr = self._get_igmpclient_field(hkey, 'grp_attr')

        if version == 2:
            for gkey in grps:
                self._tgn_send_igmpv2leave(hkey, gkey)
        elif version == 3:
            for gkey in grps:
                for skey in grp_attr[gkey]:
                    self._tgn_send_igmpv3leave(hkey, gkey, skey)

        self._update_igmpclient_field(hkey, 'state', 'idle')

        # after receiving leave message, igmp snooping will
        # send queries and wait for response
        # we send dummy join messages to pretend a real igmp client
        time.sleep(2)
        intf, ip = hkey.split(',')
        for host in self.igmp_clients[intf]:
            if self._get_igmpclient_field(host, 'state') == 'running':
                self._start_igmpclient(host)

    # ======================================================
    # Pagent ICE is not used because of following limitations:
    # 1. Client is managed per interface
    # 2. Client id is the sequence number in the client queue
    # 3. Client id will be dynamically changed if the client queue is modified
    #    when a client is removed from the queue
    # 4. No IGMP configuration is allowed when igmp client is running on the
    #    interface
    # 5. IGMPv3 Client support multiple group records, but pagent does not
    #    support update specific record, only choice is delete then add
    # 6. If multiple IGMPv3 clients exist on same interface, we can stop
    #    a specific client, but restart will possible start all clients
    # 7. IGMPv2 Leave message is illegal, whose destination mac is mapped using
    #    igmp group ip not destination ip.
    # 8. ICE does not support vlan id, but we can use subinteface for vlan
    #    encapsulation
    # 9. Pagent crashes after performing several stop/start action on multiple
    #    ICE igmpv3 client
    # ======================================================

    # ======================================================
    # Pagent TGN APIs
    # ======================================================
    def _tgn_client_mac_by_ip(self, ip):
        '''Generate a unique mac by ip address
           Args:
             ip ('str'): ip address
           Returns:
             mac address
        '''
        map_addr = int(ipaddress.ip_address(ip))
        map_addr = map_addr & 0x7FFFFF
        mac = 'aabb.bb%02X.%04X' % (map_addr >> 16, map_addr & 0xFFFF)
        return mac

    def _tgn_send_igmpv2join(self, hkey, gkey):
        '''Simulate sending a igmpv2 join message from specified host
           Args:
             hkey ('str'): host key of igmp client
             gkey ('str'): group key of igmp group member
           Returns:
             None
        '''
        log.info('TGN send igmpv2 join for client {hkey}'.format(hkey=hkey))
        interface, client_ip = hkey.split(',')

        c_name = self._get_igmpclient_field(hkey, 'name')
        smac = self._tgn_client_mac_by_ip(client_ip)
        group = self.mcast_grps[gkey]['grp_ip']
        vlan = self._get_igmpclient_field(hkey, 'vlan')

        flow = PG_flow_igmpv2_report(c_name, smac, client_ip, group, vlan)
        self.pg.send_traffic(flow, interface, 1)
        self.pg.clear_tgn()

    def _tgn_send_igmpv2leave(self, hkey, gkey):
        '''Simulate sending a igmpv2 leave message from specified host
           Args:
             hkey ('str'): host key of igmp client
             gkey ('str'): group key of igmp group member
           Returns:
             None
        '''
        log.info('TGN send igmpv2 leave for client {hkey}'.format(hkey=hkey))
        interface, client_ip = hkey.split(',')
        c_name = self._get_igmpclient_field(hkey, 'name')
        smac = self._tgn_client_mac_by_ip(client_ip)
        group = self.mcast_grps[gkey]['grp_ip']
        vlan = self._get_igmpclient_field(hkey, 'vlan')

        flow = PG_flow_igmp_leave(c_name, smac, client_ip, group, vlan)
        self.pg.send_traffic(flow, interface, 1)
        self.pg.clear_tgn()

    def _tgn_send_igmpv3join(self, hkey, gkey, skey):
        '''Simulate sending a igmpv3 join message from specified host
           Args:
             hkey ('str'): host key of igmp client
             gkey ('str'): group key of igmp group member
             skey ('str'): source key of igmp group member
           Returns:
             None
        '''
        log.info('TGN send igmpv3 join for client {hkey}'.format(hkey=hkey))
        interface, client_ip = hkey.split(',')
        grp_attr = self._get_igmpclient_field(hkey, 'grp_attr')
        vlan = self._get_igmpclient_field(hkey, 'vlan')
        c_name = self._get_igmpclient_field(hkey, 'name')
        smac = self._tgn_client_mac_by_ip(client_ip)

        group = self.mcast_grps[gkey]['grp_ip']

        if skey == "None":
            src_num = 0
            src_list = []
        else:
            src_num = self.mcast_srcs[skey]['src_num']
            src_list = self._get_ippool_ips(self.mcast_srcs[skey]['src_ip'],
                                            self.mcast_srcs[skey]['steps'],
                                            src_num)

        if grp_attr[gkey][skey]['fmode'] == 'include':
            mode = 1
        else:
            mode = 2

        flow = PG_flow_igmpv3_report(c_name, smac, client_ip, group,
                                     src_num, src_list, mode, vlan)
        self.pg.send_traffic(flow, interface, 1)
        self.pg.clear_tgn()

    def _tgn_send_igmpv3leave(self, hkey, gkey, skey):
        '''Simulate sending a igmpv3 leave message from specified host
           Args:
             hkey ('str'): host key of igmp client
             gkey ('str'): group key of igmp group member
             skey ('str'): source key of igmp group member
           Returns:
             None
        '''
        log.info('TGN send igmpv3 leave for client {hkey}'.format(hkey=hkey))
        interface, client_ip = hkey.split(',')
        grp_attr = self._get_igmpclient_field(hkey, 'grp_attr')
        vlan = self._get_igmpclient_field(hkey, 'vlan')

        c_name = self._get_igmpclient_field(hkey, 'name')
        smac = self._tgn_client_mac_by_ip(client_ip)

        group = self.mcast_grps[gkey]['grp_ip']

        if grp_attr[gkey][skey]['fmode'] == 'include':
            mode = 6
            src_num = self.mcast_srcs[skey]['src_num']
            src_list = self._get_ippool_ips(self.mcast_srcs[skey]['src_ip'],
                                            self.mcast_srcs[skey]['steps'],
                                            src_num)
        else:
            mode = 3
            src_num = 0
            src_list = []

        flow = PG_flow_igmpv3_report(c_name, smac, client_ip, group,
                                     src_num, src_list, mode, vlan)
        self.pg.send_traffic(flow, interface, 1)
        self.pg.clear_tgn()
