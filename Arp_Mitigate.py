from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.ofproto import ether
from ryu.lib.packet import dhcp
import logging

# data structures to store Ip and MAC address of host
# and count of ARP packets per port
host = {}
PortCount = {}

class SimpleSwitch13(app_manager.RyuApp):
    # specify the openflow protocol to be used for the application here it is Open flow 1.3
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION] 
    
    # override the superclass init method and initialize mac_to_port table
    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    #This Function is called whenever EventOFPSwitchFeatures is triggered, that is when a new switch connects to the controller
    #It installs the table-miss flow entry as well as ARP packet entry so that the packets are sent to the controller.
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):

        # parsing of the packet
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        # install ARP -packet match entry
        match = parser.OFPMatch(eth_type = ether.ETH_TYPE_ARP)
        self.add_flow(datapath, 2, match,actions)

    #add_flow is a helper function used to reduce the code in the controller application
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
      
        # prepare a list of instructions
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        #Constructing the flow mod
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                          match=match, instructions=inst)
         
         # Sending the flow mod
        datapath.send_msg(mod)

   #handle_spoof method is used to apply actions to the packet and match against the in_port so as to block the attacker on that port for a specific time
    def handle_spoof(self,mac,msg):
        actions = []
        in_port = msg.match['in_port']
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_CLEAR_ACTIONS,[])]
        match = parser.OFPMatch(in_port = in_port)
        mod = parser.OFPFlowMod(datapath = datapath, match = match,idle_timeout = 60, hard_timeout = 60, priority = 20, instructions = inst)
        datapath.send_msg(mod)
        self.logger.info("\033[1;31m"+"Installed an entry to drop all the packets from the port %s "+"\033[0m",in_port)


    #_arp_handler method is used to decode the packet and extract the ARP headers for the source and destination IP & MAC addresses
    # This method, check for the port count when a flood attack also takes place, so that the arp packet counts are checked for the threshold and 
    #  If the count is above threshold handle_spoof method is called which blocks the attacker for specific time.
    def _arp_handler(self,pkt_arp,msg):
        #decode the packet to get the mac and ip addresss
        arp_src_ip = pkt_arp.src_ip
        arp_dst_ip = pkt_arp.dst_ip
        arp_src_mac = pkt_arp.src_mac
        arp_dst_mac = pkt_arp.dst_mac
        port = msg.match['in_port']

        #check the count of arp packet per port
        if port not in PortCount:
                PortCount.update({port:1})
        else:
                if PortCount[port]>20:
                        self.logger.info("\033[1;31m"+"\n ARP Flood Attack detected !!!"+"\033[0m")
                        self.handle_spoof(arp_src_mac,msg)
                        return True
                elif str(pkt_arp.opcode)== str(1):
                        PortCount[port] += 1

        #check for the source ip and mac address if they match, and if they don’t alert as spoof has been occurred
        self.logger.info(" Source IP %s Dest IP:%s Source MAC:%s  Dest MAC:%s", arp_src_ip,arp_dst_ip,arp_src_mac,arp_dst_mac)
        if arp_src_ip in host.keys():
                if str(host[arp_src_ip]) != str(arp_src_mac):
                        self.logger.info("\033[1;31m"+"\n******ARP spoofing  detected: MAC and IP do not match *****"+"\033[0m")
                        self.handle_spoof(arp_src_mac,msg)
                        return True
        return False
    
    #_dhcp_handler  method extracts the DHCP headers from the received packet to populate the host table.
    #host table is used to store a list of correlation of IP address to MAC address and treated as authentic table for further analysis
    def _dhcp_handler(self, pkt_dhcp):
        #decode the packet to get the ip address and mac address; check for the opcode = 2
        if str(pkt_dhcp.op)==str(2):
                self.logger.info("\033[1;34m"+"DHCP packet"+"\033[0m")
                self.logger.info("\033[1;34m"+"IP address by dhcp : %s MAC address by dhcp %s Opcode %s"+"\033[0m",pkt_dhcp.yiaddr, pkt_dhcp.chaddr,pkt_dhcp.op)
                host.update({str(pkt_dhcp.yiaddr):str(pkt_dhcp.chaddr)})
                self.logger.info("%s",host)
        return

    
    #This is the main logic of the controller application, which is called when the switch sets a packet to the controller
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):

        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        #self.logger.info("packet info - %s" , pkt)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return

        dst = eth.dst
        src = eth.src


        dpid = datapath.id
        #GET SWitch ID
        #self.logger.info("Switch Id : %s ", dpid)


        # to check ARP packet and DHCP packet
        pkt_arp = pkt.get_protocol(arp.arp)
        pkt_dhcp = pkt.get_protocol(dhcp.dhcp)

        if pkt_arp:
        #call to arp_handler
                if self._arp_handler(pkt_arp,msg):
                        #drop
                        return

        #call to dhcp_handler
        if pkt_dhcp:
                self._dhcp_handler(pkt_dhcp)



        self.mac_to_port.setdefault(dpid, {})

        #self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:

           out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]


        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)


        data = None

        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
