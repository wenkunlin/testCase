# -*- coding: utf-8 -*-
'''基础测试例, 其他测试例继承自该测试例
'''
from testbase.conf import settings
from sdnlib.ntb_base import NtbTestCase
from testbase.testcase import debug_run_all
from sdnlib.ptf.mask import Mask
from sdnlib.ptf import testutils
from utils.utils import *
from scapy.all import rdpcap
from scapy.all import Ether
from scapy.all import IP
from scapy.all import UDP
from scapy.all import TCP
from scapy.all import ICMP
from scapy.all import VXLAN
from scapy.all import GRE
from scapy.all import ARP
from scapy.all import Dot1Q

from scapy.all import IPv6
from scapy.all import ICMPv6EchoReply
from scapy.all import ICMPv6EchoRequest
from scapy.all import RouterAlert
from scapy.all import HAO
from scapy.all import Jumbo
from scapy.all import IPv6ExtHdrRouting
from scapy.all import IPv6ExtHdrHopByHop
from scapy.all import IPv6ExtHdrFragment
from scapy.all import IPv6ExtHdrDestOpt
from scapy.all import ICMPv6ND_NS
from scapy.all import ICMPv6NDOptSrcLLAddr
from scapy.all import ICMPv6ND_NA
from scapy.all import ICMPv6NDOptDstLLAddr
from scapy.all import ICMPv6PacketTooBig
from scapy.all import ICMPv6TimeExceeded

import codecs
import sdnlib.ptf.dataplane as dataplane
import grpc
import time
from sdnlib.common import utils
from collections import Counter
import os
import socket
import ipaddress
import re
import pdb

import sdnlib.grpc_factory.ntb_pb2.ntb_config_pb2 as ntb_config_pb2
import sdnlib.grpc_factory.ntb_pb2.ntb_config_pb2_grpc as ntb_config_pb2_grpc
from google.protobuf.json_format import ParseDict
from google.protobuf.any_pb2 import Any

filter_underlay_sip   = ""
filter_underlay_dip   = ""
filter_underlay_sport = 0
filter_underlay_dport = 0
filter_underlay_vni   = 0
filter_underlay_vpcid = 0

def underlay_sip_fwdip_filter(pkt_str):
    try:
        pkt = Ether(pkt_str)
        if IP in pkt:
            if pkt[IP].src == filter_underlay_sip:
                return True
            else:
                return False
        else:
            return False
    except:
        return False

class NTBTestBase(NtbTestCase):
    """
    NTB测试例基类,封装配置下发接口
    """

    def pre_test(self):
        self._setup_client()
        self.ntb_grpc_client.connect()
        super(NTBTestBase, self).pre_test()
        self.set_hash_algo("default")
        self.set_hash_seed(0)

    def post_test(self):
        super(NTBTestBase, self).post_test()

    def _is_ipv4(self, ip):
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
            return False

    def _encap_ip_item(self, ipaddr, family=''):
        """
        封装grpc使用的ip对象
        :param ipaddr: ip地址, eg: 1.1.1.1
        :param famliy: 地址协议簇, ipv4 或者 ipv6
        :return
        """
        if self._is_ipv4(ipaddr):
            return {"ipAddr": ip_to_int(ipaddr), "ip6Addr": "", "family": 1}
        else:
            return {"ipAddr": 0, "ip6Addr": ipaddr, "family": 2}

    def _encap_prefix_item(self, ipaddr, plen, family):
        """
        封装grpc使用的prefix对象
        :param ipaddr: ip地址, eg:1.1.1.1 
        :param plen: 前缀长度
        :param famliy: 地址协议簇, ipv4 或者 ipv6
        :return
        """
        item = {}
        if self._is_ipv4(ipaddr):
            item["family"] = 1
        else:
            item["family"] = 2
        item["prefixLen"] = plen
        item["ipAddr"] = self._encap_ip_item(ipaddr, "")
        return item

    def _parse_ipaddr_dict(self, ipaddr):
        """
        解析grpc ipaddr对象
        :param ipaddr: ip地址 grpc对象
        :return family, ip
        """
        family = ipaddr["family"]
        if family == 2:
            ip = ipaddr["ip6Addr"]
        else:
            ip = int_to_ip(ipaddr["ipAddr"])

        return family, ip

    def _parse_prefix_dict(self, prefix):
        """
        解析grpc prefix对象
        :param prefix: prefix grpc对象
        :return family, ip, plen
        """
        pfamily = prefix["family"]
        if pfamily == 2:
            pip = prefix["ipAddr"]["ip6Addr"]
        else:
            pip = int_to_ip(prefix["ipAddr"]["ipAddr"])
        plen = prefix["prefixLen"]

        return pfamily, pip, plen

    def _parse_prefix_dict_normalized(self, prefix):
        """
        解析grpc prefix对象
        :param prefix: prefix grpc对象
        :return family, ip, plen
        """
        pfamily = prefix["family"]
        if pfamily == 2:
            pip = prefix["ipAddr"]["ip6Addr"]
        else:
            pip = int_to_ip(prefix["ipAddr"]["ipAddr"])
        plen = prefix["prefixLen"]
        prefix_str = "%s/%d" % (pip, plen)
        network = ipaddress.ip_network(prefix_str, strict=False)
        pip = str(network.network_address)
        plen = network.prefixlen
        return pfamily, pip, plen

    def _parse_vrf(self, vrf):
        return {
            "vrfName": vrf,
        }

    def dict_to_grpc_any(self, data, grpc_message):
        """
        将字典转换为 gRPC Any 类型。

        :param data: 要转换的字典
        :param grpc_message: gRPC 消息类的实例
        :return: 包含 gRPC 消息的 Any 对象
        """
        # 使用 ParseDict 将字典转换为 gRPC 消息
        ParseDict(data, grpc_message, ignore_unknown_fields=True)

        # 创建 Any 对象并将 gRPC 消息打包
        any_message = Any()
        any_message.Pack(grpc_message)

        return any_message

    # -------------------------------createVrf/deleteVrf grpc---------------------------------------------------#
    def _check_vrf_res(self, vrfname, op, res, expect_res):
        vrf_exits_in_device = False
        cfgtypes = ["tunnelVxlans"]
        in_device_cfgs = self.ntb_grpc_client.get_ntb_vrf_config(vrfname, cfgtypes)
        if "vrfInfo" in in_device_cfgs:
            vrf_exits_in_device = True

        if res["result"]["info"] != expect_res:
            self.log_info("%s vrf %s result not expected, expect %s but %s" %
                          (op, vrfname, expect_res, res["result"]["info"]))
            return False

        if op == "create":
            if expect_res == "success":
                if not vrf_exits_in_device:
                    self.log_info("%s vrf %s success, but not set in device" % (op, vrfname))
                    return False
        else:
            if expect_res == "success":
                if vrf_exits_in_device:
                    self.log_info("%s vrf %s success, but still in device" % (op, vrfname))
                    return False
        return True

    def _handle_vrf(self, vrfname, op, expect_res, check=True):
        """
        下发vrf配置
        """
        dict_request = {
            "vrf": {
                "vrfName": vrfname
            }
        }

        grpc_ret = None
        if op == "create":
            grpc_ret = self.ntb_grpc_client.grpc_call("createVrf", dict_request)
        else:
            grpc_ret = self.ntb_grpc_client.grpc_call("deleteVrf", dict_request)
        if check:
            self.assert_("%s vrf faild, not expected" % (op),
                     self._check_vrf_res(vrfname, op, grpc_ret, expect_res))
        else:
            self.assert_("%s vrf faild, not expected" % (op), (grpc_ret["result"]["info"] == expect_res))


    def create_vrf(self, vrfname, expect_res="success", check=True):
        """
        创建vrf
        :param vrfname: vrf名
        :param expect_res: 期待grpc执行结果
        :return
        """
        self._handle_vrf(vrfname, "create", expect_res, check)

    def delete_vrf(self, vrfname, expect_res="success", check=True):
        """
        删除vrf
        :param vrfname: vrf名
        :param expect_res: 期待grpc执行结果
        :return
        """
        self._handle_vrf(vrfname, "delete", expect_res, check)

    # -------------------------------createIpTable/deleteIpTable grpc---------------------------------------------------#
    def _check_IpTable_res(self, vrfname, op, tableId, res, expect_res):
        in_device_tables = {}
        cfgtypes = ["ipTables"]
        in_device_cfgs = self.ntb_grpc_client.get_ntb_vrf_config(vrfname, cfgtypes)
        for i in in_device_cfgs['ipTables']:
            tbl_id = i['tableId']
            in_device_tables[tbl_id] = True
        if expect_res != res['result']['info']:
            self.log_info("%s iptable %s result not expected, expect %s but %s" % (
                op, tableId, expect_res, res["result"]["info"]))
            return False
        if op == 'create':
            if expect_res == 'success':
                if tableId not in in_device_tables:
                    self.log_info("%s iptable %s success, but not in device" % (op, tableId))
                    return False
        else:
            if expect_res == 'success':
                if tableId in in_device_tables:
                    self.log_info("%s iptable %s success, but still in device" % (op, tableId))
                    return False
        return True

    def _handle_IpTable(self, vrfname, tableId, op, expect_res):
        """
        下发IpTable配置
        """
        dict_request = {
            "vrf": {
                "vrfName": vrfname
            },
            "family": 0,
            "tableId": tableId
        }

        grpc_ret = None
        if op == "create":
            grpc_ret = self.ntb_grpc_client.grpc_call("createIpTable", dict_request)
        else:
            grpc_ret = self.ntb_grpc_client.grpc_call("deleteIpTable", dict_request)

        self.assert_("%s IpTable faild, not expected" % (op),  
                    self._check_IpTable_res(vrfname, op, tableId, grpc_ret, expect_res))

    def create_ip_table(self, vrfname, tableId, expect_res="success"):
        """
        创建vrf
        :param vrfname: vrf名
        :param tableId: tableId
        :param expect_res: 期待grpc执行结果
        :return
        """
        self._handle_IpTable(vrfname, tableId, "create", expect_res)

    def delete_ip_table(self, vrfname, tableId, expect_res="success"):
        """
        删除vrf
        :param vrfname: vrf名
        :param tableId: tableId
        :param expect_res: 期待grpc执行结果
        :return
        """
        self._handle_IpTable(vrfname, tableId, "delete", expect_res)

    def get_vrf_config(self, vrfname):
        """
        """
        cfgtypes = []
        in_device_cfgs = self.ntb_grpc_client.get_ntb_vrf_config(vrfname, cfgtypes)
        return in_device_cfgs

    # -------------------------------setVrfRMac/unsetVrfRMac grpc---------------------------------------------------#
    def _check_vrf_mac_res(self, vrfname, routemac, op, res, expect_res):
        default_mac = "3c:fd:fe:29:cb:c2"
        routemac_in_device = ""
        cfgtypes = ["routeMacs"]
        in_device_cfgs = self.ntb_grpc_client.get_ntb_vrf_config(vrfname, cfgtypes)
        if len(in_device_cfgs["routeMacs"]) != 0:
            routemac_in_device = in_device_cfgs["routeMacs"][0]["mac"]

        if res["info"] != expect_res:
            self.log_info("%s vrf %s mac %s result not expected, expect %s but %s" %
                          (op, vrfname, routemac, expect_res, res["info"]))
            return False

        if op == "set":
            if expect_res == "success":
                if routemac != routemac_in_device:
                    self.log_info("%s vrf %s mac %s success, but %s inconsitent with %s in device" %
                                  (op, vrfname, routemac, routemac_in_device))
                    return False
        else:
            if expect_res == "success":
                if default_mac != routemac_in_device and routemac_in_device != "":
                    self.log_info("%s vrf %s mac %s success, but device %s not set to default %s" %
                                  (op, vrfname, routemac, routemac_in_device, default_mac))
                    return False
        return True

    def _handle_vrf_mac(self, vrfname, routemac, op, expect_res):
        """
        下发vrf配置
        """
        dict_request = {
            "vrf": {
                "vrfName": vrfname
            },
            "routeMac": routemac
        }

        grpc_ret = None
        if op == "set":
            grpc_ret = self.ntb_grpc_client.grpc_call("setVrfRMac", dict_request)
        else:
            grpc_ret = self.ntb_grpc_client.grpc_call("unsetVrfRMac", dict_request)

        self.assert_("%s vrf mac faild, not expected" % (op),
                     self._check_vrf_mac_res(vrfname, routemac, op, grpc_ret, expect_res))

    def set_vrf_mac(self, vrfname, routemac, expect_res="success"):
        """
        创建vrf mac
        :param vrfname: vrf名
        :param routemac: 要配置的mac地址
        :param expect_res: 期待grpc执行结果
        :return
        """
        self._handle_vrf_mac(vrfname, routemac, "set", expect_res)

    def unset_vrf_mac(self, vrfname, routemac, expect_res="success"):
        """
        删除vrf mac
        :param vrfname: vrf名
        :param routemac: 要配置的mac地址
        :param expect_res: 期待grpc执行结果
        :return
        """
        self._handle_vrf_mac(vrfname, routemac, "unset", expect_res)

    # -------------------------------addVrfIp/delVrfIp grpc---------------------------------------------------#
    def _check_vrf_ip_res(self, vrfname, op, res, expect_res, isv4=True, vrf_ip_type=2):
        vrf_ip_exits_in_device = False
        vrf_ip = None
        if isv4:
            cfgtypes = ["internalVrfIp"]
            in_device_cfgs = self.ntb_grpc_client.get_ntb_vrf_config(vrfname, cfgtypes)
            if "internalVrfIp" in in_device_cfgs:
                vrf_ip_exits_in_device = True
                vrf_ip = in_device_cfgs["internalVrfIp"]
        else:
            if vrf_ip_type == 2:
                cfgtypes = ["internalVrfIp6"]
                in_device_cfgs = self.ntb_grpc_client.get_ntb_vrf_config(vrfname, cfgtypes)
                if "internalVrfIp6" in in_device_cfgs:
                    vrf_ip_exits_in_device = True
                    vrf_ip = in_device_cfgs["internalVrfIp6"]
            else:
                cfgtypes = ["vpcIp6"]
                in_device_cfgs = self.ntb_grpc_client.get_ntb_vrf_config(vrfname, cfgtypes)
                if "vpcIp6" in in_device_cfgs:
                    vrf_ip_exits_in_device = True
                    vrf_ip = in_device_cfgs["vpcIp6"]

        if res[0]["result"]["info"] != expect_res:
            self.log_info("%s vrf %s vrfip result not expected, expect %s but %s" %
                          (op, vrfname, expect_res, res[0]["result"]["info"]))
            return False

        if op == "create":
            if expect_res == "success":
                if not vrf_ip_exits_in_device:
                    self.log_info("%s vrf %s vrfip success, but not set in device" % (op, vrfname))
                    return False
                if res[0]["rtIpInfo"] != vrf_ip:
                    self.log_info("%s vrf %s vrfip success, but %s inconsitent with %s in device" %
                                  (op, vrfname, str(res[0]["rtIpInfo"]), str(vrf_ip)))
                    return False
        else:
            if expect_res == "success":
                if vrf_ip_exits_in_device:
                    self.log_info("%s vrf %s vrfip success, but still set in device" % (op, vrfname))
                    return False
        return True

    def _handle_vrf_ip(self, vrfname, vrf_ip, op, expect_res, check=True):
        """
        下发vrf_ip
        """
        dict_request = {
            "vrf": {
                "vrfName": vrfname
            },
            "rtIpInfoes": []
        }

        item = {}
        isv4 = True
        if self._is_ipv4(vrf_ip["prefix"]):
            isv4 = True
        else:
            isv4 = False

        item["ip"] = self._encap_prefix_item(vrf_ip["prefix"], vrf_ip["plen"], "ipv4")
        vrf_ip_type = 0
        if vrf_ip["type"] == "VRF_IP_TYPE_NULL":
            vrf_ip_type = 0
        elif vrf_ip["type"] == "VRF_VPCIP":
            vrf_ip_type = 1
        else:
            vrf_ip_type = 2
        item["type"] = vrf_ip_type
        dict_request["rtIpInfoes"].append(item)

        grpc_ret = None
        if op == "create":
            grpc_ret = self.ntb_grpc_client.grpc_call("addVrfIp", dict_request)
        else:
            grpc_ret = self.ntb_grpc_client.grpc_call("delVrfIp", dict_request)

        self.assert_("%s vrf ip faild, not expected" % (op),
                     self._check_vrf_ip_res(vrfname, op, grpc_ret["rtIpInfoResults"], expect_res, isv4, vrf_ip_type))

    def create_vrf_ip(self, vrfname, vrf_ip, expect_res="success", check=True):
        """
        创建vrf vip
        :param vrfname: vrf名
        :param vrf_ip: vrf_ip对象 {"prefix": "1.1.1.1", "plen": 32, "type": "VRF_IP_TYPE_NULL"}
        :param expect_res: 期待grpc执行结果
        :return
        """
        self._handle_vrf_ip(vrfname, vrf_ip, "create", expect_res, check)

    def delete_vrf_ip(self, vrfname, vrf_ip, expect_res="success", check=True):
        """
        删除vrf vip
        :param vrfname: vrf名
        :param vrf_ip: vrf_ip对象 {"prefix": "1.1.1.1", "plen": 32, "type": "VRF_IP_TYPE_NULL"}
        :param expect_res: 期待grpc执行结果
        :return
        """
        self._handle_vrf_ip(vrfname, vrf_ip, "delete", expect_res, check)

    # -------------------------------addVrfTunnelBundleVxlan/delVrfTunnelBundleVxlan grpc-----------------------#
    def _check_vxlan_tunnel_bundle_res(self, vrfname, op, res, expect_res):
        in_device_tunnelvxlanbundles = {}
        cfgtypes = ["tunnelBundleVxlans"]
        in_device_cfgs = self.ntb_grpc_client.get_ntb_vrf_config(vrfname, cfgtypes)
        for tunvxlanbundle in in_device_cfgs["tunnelBundleVxlans"]:
            key = "%s-%s" % (tunvxlanbundle["vxlanVni_i"], tunvxlanbundle["vxlanVni_o"])
            in_device_tunnelvxlanbundles[key] = tunvxlanbundle

        for item in res:
            key = "%s-%s" % (item["tunnelBundle"]["vxlanVni_i"], item["tunnelBundle"]["vxlanVni_o"])
            value = item["tunnelBundle"]
            e_res = expect_res[key]
            if e_res != item["result"]["info"]:
                self.log_info("%s vxlan tunnel bundle %s result not expected, expect %s but %s" % (
                    op, key, e_res, item["result"]["info"]))
                return False
            if op == "create":
                if e_res == "success":
                    if key not in in_device_tunnelvxlanbundles:
                        self.log_info("%s vxlan tunnel bundle %s success, but not in device" % (op, key))
                        return False
                    if value != in_device_tunnelvxlanbundles[key]:
                        self.log_info("%s vxlan tunnel bundle %s success, but %s inconsitent with %s in device" %
                                      (op, key, value, in_device_tunnelvxlanbundles[key]))
                        return False
            else:
                if e_res == "success":
                    if key in in_device_tunnelvxlanbundles:
                        self.log_info("%s vxlan tunnel bundle %s success, but still in device" % (op, key))
                        return False
        return True

    def _handle_vxlan_tunnel_bundle(self, vrfname, vxlan_tun_bundle_list, op, check=True):
        """
        下发vxlan隧道防环
        """
        if len(vxlan_tun_bundle_list) == 0:
            return
        dict_request = {
            "vrf": {
                "vrfName": vrfname
            },
            "tunnelBundles": [
            ]
        }
        expect_res = {}
        for vxlan_tun_bundle in vxlan_tun_bundle_list:
            item = {}
            item["vxlanVni_i"] = vxlan_tun_bundle["ivni"]
            item["vxlanVni_o"] = vxlan_tun_bundle["ovni"]
            dict_request["tunnelBundles"].append(item)
            expect_key = "%s-%s" % (vxlan_tun_bundle["ivni"], vxlan_tun_bundle["ovni"])
            if "expect_res" not in vxlan_tun_bundle:
                vxlan_tun_bundle["expect_res"] = "success"
            expect_res[expect_key] = vxlan_tun_bundle["expect_res"]
        grpc_ret = None
        if op == "create":
            grpc_ret = self.ntb_grpc_client.grpc_call("addVrfTunnelBundleVxlan", dict_request)
        else:
            grpc_ret = self.ntb_grpc_client.grpc_call("delVrfTunnelBundleVxlan", dict_request)
        if check:
            self.assert_("%s vxlan tunnel bundle faild, not expected" % (op),
                        self._check_vxlan_tunnel_bundle_res(vrfname, op, grpc_ret["tunnelBundleCfgResults"], expect_res))
        else:
            self.assert_("%s vxlan tunnel bundle faild, not expected" % (op),
                        grpc_ret["result"]["info"] == "success")

    def create_vxlan_tunnel_bundle(self, vrfname, vxlan_tun_bundle_list, check=True):
        """
        创建vxlan隧道防环
        :param vrfname: vrf name
        :param vxlan_tun_bundle_list: vxlan隧道防环 列表
            item: eg: {"ivni": 1000, "ovni": 1001, "expect_res": "success"}
        :return
        """
        self._handle_vxlan_tunnel_bundle(vrfname, vxlan_tun_bundle_list, "create", check)

    def delete_vxlan_tunnel_bundle(self, vrfname, vxlan_tun_bundle_list, check=True):
        """
        删除vxlan隧道防环
        :param vrfname: vrf name
        :param vxlan_tun_bundle_list: vxlan隧道 列表
            item: eg: {"ivni": 1000, "ovni": 1001, "expect_res": "success"}
        :return
        """
        self._handle_vxlan_tunnel_bundle(vrfname, vxlan_tun_bundle_list, "delete", check)

    # -------------------------------addVrfTunnelVxlan/delVrfTunnelVxlan grpc-----------------------#
    def _check_vxlan_tunnel_res(self, vrfname, op, res, expect_res):
        in_device_tunnelvxlans = {}
        cfgtypes = ["tunnelVxlans"]
        in_device_cfgs = self.ntb_grpc_client.get_ntb_vrf_config(vrfname, cfgtypes)
        for tunvxlan in in_device_cfgs["tunnelVxlans"]:
            vni = tunvxlan["vxlanVni"]
            in_device_tunnelvxlans[vni] = tunvxlan

        for item in res:
            key = item["tunnelVxlan"]["vxlanVni"]
            value = item["tunnelVxlan"]
            if value["rpf"] != 0:
                value["rpf"] = 1
            e_res = expect_res[key]
            if e_res != item["result"]["info"]:
                self.log_info("%s vxlan tunnel %s result not expected, expect %s but %s" % (
                    op, key, e_res, item["result"]["info"]))
                return False
            if op == "create":
                if e_res == "success":
                    if key not in in_device_tunnelvxlans:
                        self.log_info("%s vxlan tunnel %s success, but not in device" % (op, key))
                        return False
                    if value != in_device_tunnelvxlans[key]:
                        self.log_info("%s vxlan tunnel %s success, but %s inconsitent with %s in device" %
                                      (op, key, value, in_device_tunnelvxlans[key]))
                        return False
            else:
                if e_res == "success":
                    if key in in_device_tunnelvxlans:
                        self.log_info("%s vxlan tunnel %s success, but still in device" % (op, key))
                        return False
        return True

    def _handle_vxlan_tunnel(self, vrfname, vxlan_tun_list, op, check=True):
        """
        下发vxlan隧道 
        """
        if len(vxlan_tun_list) == 0:
            return
        dict_request = {
            "vrf": {
                "vrfName": vrfname
            },
            "tunnelVxlans": [
            ]
        }
        expect_res = {}
        for vxlan_tun in vxlan_tun_list:
            item = {}
            item["vxlanVni"] = vxlan_tun["vni"]
            if "urpf" not in vxlan_tun:
                item["rpf"] = 0
            else:
                item["rpf"] = vxlan_tun["urpf"]

            if "rt_table" not in vxlan_tun:
                item["tableId"] = 0
            else:
                item["tableId"] = vxlan_tun["rt_table"]
            dict_request["tunnelVxlans"].append(item)
            expect_key = vxlan_tun["vni"]
            if "expect_res" not in vxlan_tun:
                vxlan_tun["expect_res"] = "success"
            expect_res[expect_key] = vxlan_tun["expect_res"]
        grpc_ret = None
        if op == "create":
            grpc_ret = self.ntb_grpc_client.grpc_call("addVrfTunnelVxlan", dict_request)
        else:
            grpc_ret = self.ntb_grpc_client.grpc_call("delVrfTunnelVxlan", dict_request)
        if check:
            self.assert_("%s vxlan tunnel faild, not expected" % (op),
                        self._check_vxlan_tunnel_res(vrfname, op, grpc_ret["tunnelVxlanCfgResults"], expect_res))
        else:
            self.assert_("%s vxlan tunnel faild, not expected" % (op),
                        grpc_ret["result"]["info"] == "success")

    def create_vxlan_tunnel(self, vrfname, vxlan_tun_list, check=True):
        """
        创建vxlan隧道 
        :param vrfname: vrf name
        :param vxlan_tun_list: vxlan隧道 列表
            item: eg: {"vni": 100, "urpf": 1, "rt_table": 1, "expect_res": "success"}
        :return
        """
        self._handle_vxlan_tunnel(vrfname, vxlan_tun_list, "create", check)

    def delete_vxlan_tunnel(self, vrfname, vxlan_tun_list, check=True):
        """
        删除vxlan隧道 
        :param vrfname: vrf name
        :param vxlan_tun_list: vxlan隧道 列表
            item: eg: {"vni": 100, "urpf": 1, "rt_table": 1, "expect_res": "success"}
        :return
        """
        self._handle_vxlan_tunnel(vrfname, vxlan_tun_list, "delete", check)

    # -------------------------------addVrfTunnelGre/delVrfTunnelGre grpc-----------------------#
    def _check_gre_tunnel_res(self, vrfname, op, res, expect_res):
        in_device_tunnelgres = {}
        cfgtypes = ["tunnelGres"]
        in_device_cfgs = self.ntb_grpc_client.get_ntb_vrf_config(vrfname, cfgtypes)
        for tungre in in_device_cfgs["tunnelGres"]:
            vpcid = tungre["greVpcId"]
            in_device_tunnelgres[vpcid] = True

        for item in res:
            key = item["tunnelGre"]["greVpcId"]
            e_res = expect_res[key]
            if e_res != item["result"]["info"]:
                self.log_info(
                    "%s gre tunnel %s result not expected, expect %s but %s" % (op, key, e_res, item["result"]["info"]))
                return False
            if op == "create":
                if e_res == "success":
                    if key not in in_device_tunnelgres:
                        self.log_info("%s gre tunnel %s success, but not in device" % (op, key))
                        return False
            else:
                if e_res == "success":
                    if key in in_device_tunnelgres:
                        self.log_info("%s gre tunnel %s success, but still in device" % (op, key))
                        return False
        return True

    def _handle_gre_tunnel(self, vrfname, gre_tun_list, op, check=True):
        """
        下发gre隧道配置
        """
        if len(gre_tun_list) == 0:
            return
        dict_request = {
            "vrf": {
                "vrfName": vrfname
            },
            "tunnelGres": [
            ]
        }

        expect_res = {}
        for gre_tun in gre_tun_list:
            item = {}
            item["greVpcId"] = gre_tun["vpcid"]
            dict_request["tunnelGres"].append(item)

            expect_key = gre_tun["vpcid"]
            if "expect_res" not in gre_tun:
                gre_tun["expect_res"] = "success"
            expect_res[expect_key] = gre_tun["expect_res"]

        grpc_ret = None
        if op == "create":
            grpc_ret = self.ntb_grpc_client.grpc_call("addVrfTunnelGre", dict_request)
        else:
            grpc_ret = self.ntb_grpc_client.grpc_call("delVrfTunnelGre", dict_request)

        if check:
            self.assert_("%s gre tunnel faild, not expected" % (op),
                            self._check_gre_tunnel_res(vrfname, op, grpc_ret["tunnelGreCfgResults"], expect_res))
        else:
            self.assert_("%s gre tunnel faild, not expected" % (op),
                            grpc_ret["result"]['info'] == "success")

    def create_gre_tunnel(self, vrfname, gre_tun_list, check=True):
        """
        创建gre隧道 
        :param vrfname: vrf name
        :param gre_tun_list: gre隧道列表
            item: eg: {"vpcid": 100, "expect_res": "success"}
        :return
        """
        self._handle_gre_tunnel(vrfname, gre_tun_list, "create", check)

    def delete_gre_tunnel(self, vrfname, gre_tun_list, check=True):
        """
        删除gre隧道 
        :param vrfname: vrf name
        :param gre_tun_list: gre隧道列表
            item: eg: {"vpcid": 100, "expect_res": "success"}
        :return
        """
        self._handle_gre_tunnel(vrfname, gre_tun_list, "delete", check)

    # -------------------------------setVrfArpEntry/getVrfAllArpEntry grpc-----------------------#
    def _check_overlay_arp_res(self, vrfname, op, res, expect_res):
        in_device_arps = self.get_vrf_all_arp(vrfname)

        for item in res:
            _, key = self._parse_ipaddr_dict(item["arpEntry"]["ip"])
            value = item["arpEntry"]
            e_res = expect_res[key]
            if e_res != item["result"]["info"]:
                self.log_info("%s overlay arp %s result not expected, expect %s but %s" % (
                    op, key, e_res, item["result"]["info"]))
                return False
            if op == "set" or op == "get":
                if e_res == "success":
                    if key not in in_device_arps:
                        self.log_info("%s overlay arp %s success, but not in device" % (op, key))
                        return False
                    if in_device_arps[key] != value:
                        self.log_info("%s overlay arp %s success, but %s inconsitent with deivce %s" %
                                      (op, key, str(value), str(in_device_arps[key])))
                        return False
        return True

    def _handle_overlay_arp(self, vrfname, arp_list, op, check=True):
        """
        下发overlay arp配置
        """
        if len(arp_list) == 0:
            return
        dict_request = {
            "arpEntries": [
            ]
        }

        expect_res = {}
        for arp_item in arp_list:
            item = {}
            item["ip"] = self._encap_ip_item(arp_item["ip"], "ipv4")
            item["mac"] = arp_item["mac"]
            item["vrf"] = vrfname
            dict_request["arpEntries"].append(item)
            expect_key = arp_item["ip"]
            if "expect_res" not in arp_item:
                arp_item["expect_res"] = "success"
            expect_res[expect_key] = arp_item["expect_res"]

        grpc_ret = None
        if op == "set":
            grpc_ret = self.ntb_grpc_client.grpc_call("setVrfArpEntry", dict_request)
        elif op == 'get':
            grpc_ret = self.ntb_grpc_client.grpc_call("getVrfArpEntry", dict_request)
            self.assert_("getVrfArpEntry faild", grpc_ret["result"]["info"] == "success")
        elif op == 'clk':
            grpc_ret = self.ntb_grpc_client.grpc_call("clkVrfArpEntry", dict_request)
            # print(grpc_ret)
            # self.assert_("clkVrfArpEntry faild", grpc_ret["result"]["info"] == "success")
            # return


        if check:
            self.assert_("%s overlay arp faild, not expected" % (op),
                        self._check_overlay_arp_res(vrfname, op, grpc_ret["arpEntryResults"], expect_res))
        else:
            self.assert_("%s overlay arp faild, not expected" % (op),
                        grpc_ret["result"]["info"] == "success")

    def set_overlay_arp(self, vrfname, arp_list, check=True):
        """
        更新overlay arp
        :param vrfname: vrf name
        :param arp_list: arp 列表
            item: eg: {"ip": "1.1.1.1", "mac": "ac:de:48:00:11:22", "expect_res": "success"}
        :return
        """
        self._handle_overlay_arp(vrfname, arp_list, "set", check)

    def get_overlay_arp(self, vrfname, arp_list):
        """
        get overlay arp by vrf and ip 
        :param vrfname: vrf name
        :param arp_list: arp 列表
            item: eg: {"ip": "1.1.1.1", "mac": "ac:de:48:00:11:22", "expect_res": "success"}
        :return
        """
        self._handle_overlay_arp(vrfname, arp_list, "get")

    def clk_overlay_arp(self, vrfname, arp_list):
        """
        clk overlay arp by vrf and ip 
        :param vrfname: vrf name
        :param arp_list: arp 列表
            item: eg: {"ip": "1.1.1.1", "expect_res": "success"}
        :return
        """
        self._handle_overlay_arp(vrfname, arp_list, "clk")

    def _handle_vrf_arp(self, vrfname, arp_list, check=True):
        """
        下发vrf arp配置
        """
        if len(arp_list) == 0:
            return
        dict_request = {
            "vrf": {
                "vrfName": vrfname
            },
            "arpInfos": [
            ]
        }

        expect_res = {}
        for arp_item in arp_list:
            item = {}
            item["sourceIp"] = self._encap_ip_item(arp_item["sip"])
            item["targetIp"] = self._encap_ip_item(arp_item["tip"])
            item["gatewayIp"] = self._encap_ip_item(arp_item["gip"])
            dict_request["arpInfos"].append(item)
            expect_key = "%s-%s-%s" % (arp_item["sip"], arp_item["tip"], arp_item["gip"])
            if "expect_res" not in arp_item:
                arp_item["expect_res"] = "success"
            expect_res[expect_key] = arp_item["expect_res"]

        grpc_ret = None
        grpc_ret = self.ntb_grpc_client.grpc_call("triggerVrfArp", dict_request)

        for i in grpc_ret["arpInfoCfgResults"]:
            _, sip = self._parse_ipaddr_dict(i["arpInfo"]["sourceIp"])
            _, tip = self._parse_ipaddr_dict(i["arpInfo"]["targetIp"])
            _, gip = self._parse_ipaddr_dict(i["arpInfo"]["gatewayIp"])
            key = '%s-%s-%s' % (sip, tip, gip)
            if key in expect_res:
                self.assert_("trigger vrf %s %s arp faild, expect %s but %s" % 
                                (vrfname, key, expect_res[key], i['result']['info']), expect_res[key] == i['result']['info'])

    def trigger_vrf_arp(self, vrfname, arp_list):
        """
        trigger vrf arp 
        :param vrfname: vrf name
        :param arp_list: arp 列表
            item: eg: {"sip": "1.1.1.1", "tip": "1.1.1.1", "gip": "1.1.1.2", "expect_res": "success"}
        :return
        """
        self._handle_vrf_arp(vrfname, arp_list)

    def get_vrf_all_arp(self, vrfname):
        """
        获取vrf下的所有arp表项
        :param vrfname: vrf name
        :return overlay_arp map
            item: eg: {"1.1.1.1": {"ip": "1.1.1.1", "mac": "ac:de:48:00:11:22", "vrf": "test"}}
        """
        overlay_arps = {}
        grpc_ret = self.ntb_grpc_client.grpc_call("getVrfAllArpEntry", {"vrf": {"vrfName": vrfname}})
        self.assert_("getVrfAllArpEntry faild", grpc_ret["result"]["info"] == "success")
        for arp_item in grpc_ret["vrfAllEntryResults"]:
            _, key = self._parse_ipaddr_dict(arp_item["ip"])
            overlay_arps[key] = arp_item

        return overlay_arps

    # -------------------------------addVrfAgentArpIp/delVrfAgentArpIp grpc-----------------------#
    def _check_agent_arp_res(self, vrfname, op, res, expect_res):

        in_device_agentarps = {}
        cfgtypes = ["neighProxys"]
        in_device_cfgs = self.ntb_grpc_client.get_ntb_vrf_config(vrfname, cfgtypes)
        for agentarp in in_device_cfgs["neighProxys"]:
            _, tip = self._parse_ipaddr_dict(agentarp["ip"])
            if agentarp["mac"] == "00:00:00:00:00:00":
                agentarp["mac"] = ''
            in_device_agentarps[tip] = agentarp

        for item in res:
            _, key = self._parse_ipaddr_dict(item["agentArpIp"]["ip"])
            value = item["agentArpIp"]
            e_res = expect_res[key]
            if e_res != item["result"]["info"]:
                self.log_info(
                    "%s agent arp %s result not expected, expect %s but %s" % (op, key, e_res, item["result"]["info"]))
                return False
            if op == "create":
                if e_res == "success":
                    if key not in in_device_agentarps:
                        self.log_info("%s agent arp %s success, but not in device" % (op, key))
                        return False
                    if in_device_agentarps[key] != value:
                        self.log_info("%s agent arp %s success, but %s inconsitent with deivce %s" %
                                      (op, key, str(value), str(in_device_agentarps[key])))
                        return False
            else:
                if e_res == "success":
                    if key in in_device_agentarps:
                        self.log_info("%s agent arp %s success, but still in device" % (op, key))
                        return False
        return True

    def _handle_agent_arp(self, vrfname, agent_arp_list, op):
        """
        下发agent arp配置
        """
        if len(agent_arp_list) == 0:
            return
        dict_request = {
            "vrf": {
                "vrfName": vrfname
            },
            "agentArpIps": [
            ]
        }

        expect_res = {}
        for agent_arp in agent_arp_list:
            item = {}
            item["ip"] = self._encap_ip_item(agent_arp["ip"], "ipv4")
            if "mac" not in agent_arp:
                item["mac"] = ""
            else:
                item["mac"] = agent_arp["mac"]
                # item["reqip"] = self._encap_ip_item("0.0.0.0", "ipv4")
            dict_request["agentArpIps"].append(item)
            expect_key = agent_arp["ip"]
            if "expect_res" not in agent_arp:
                agent_arp["expect_res"] = "success"
            expect_res[expect_key] = agent_arp["expect_res"]

        grpc_ret = None
        if op == "create":
            grpc_ret = self.ntb_grpc_client.grpc_call("addVrfAgentArpIp", dict_request)
        else:
            grpc_ret = self.ntb_grpc_client.grpc_call("delVrfAgentArpIp", dict_request)

        self.assert_("%s agent arp faild, not expected" % (op),
                     self._check_agent_arp_res(vrfname, op, grpc_ret["agentArpIpCfgResults"], expect_res))

    def create_agent_arp(self, vrfname, agent_arp_list):
        """
        创建代答arp
        :param vrfname: vrf name
        :param agent_arp_list: 代答arp列表
            item: eg: {"ip": "1.1.1.1”, "mac": "ac:de:48:00:11:22", "expect_res": "success"}
        :return
        """
        self._handle_agent_arp(vrfname, agent_arp_list, "create")

    def delete_agent_arp(self, vrfname, agent_arp_list):
        """
        删除代答arp
        :param vrfname: vrf name
        :param agent_arp_list: 代答arp列表
            item: eg: {"ip": "1.1.1.2", "mac": "ac:de:48:00:11:22", "expect_res": "success"}
        :return
        """
        self._handle_agent_arp(vrfname, agent_arp_list, "delete")

    # -------------------------------addCrossConnect/delCrossConnect grpc-----------------------#
    def _check_xconnect_res(self, vrfname, op, res, expect_res):
        in_device_xconnect_cfgs = {}
        cfgtypes = ["xconnects"]
        in_device_cfgs = self.ntb_grpc_client.get_ntb_vrf_config(vrfname, cfgtypes)
        for xc_info in in_device_cfgs["xConnects"]:
            _, rip = self._parse_ipaddr_dict(xc_info["remoteIp"])
            in_vni = xc_info["invxlanVni"]
            out_vni = xc_info["outvxlanVni"]
            key = "%s-%s-%s" % (in_vni, rip, out_vni)
            in_device_xconnect_cfgs[key] = xc_info

        for item in res:
            _, rip = self._parse_ipaddr_dict(item["xconnect"]["remoteIp"])
            in_vni = item["xconnect"]["invxlanVni"]
            out_vni = item["xconnect"]["outvxlanVni"]
            key = "%s-%s-%s" % (in_vni, rip, out_vni)
            value = item["xconnect"]
            e_res = expect_res[key]
            if e_res != item["result"]["info"]:
                self.log_info("%s xconnect %s result not expected, expect %s but %s" % (
                    op, key, e_res, item["result"]["info"]))
                return False
            if op == "create":
                if e_res == "success":
                    if key not in in_device_xconnect_cfgs:
                        self.log_info("%s xconnect  %s success, but not set in device" % (op, key))
                        return False
                    if in_device_xconnect_cfgs[key] != value:
                        self.log_info("%s xconnect  %s success, but %s inconsitent with %s in device" %
                                      (op, key, str(value), str(in_device_xconnect_cfgs[key])))
                        return False
            else:
                if e_res == "success":
                    if key in in_device_xconnect_cfgs:
                        self.log_info("%s xconnect %s success, but still in device" % (op, key))
                        return False
        return True

    def _check_xconnect_dscp_res(self, vrfname, res, expect_res):
        in_device_xconnect_cfgs = {}
        cfgtypes = ["xconnects"]
        in_device_cfgs = self.ntb_grpc_client.get_ntb_vrf_config(vrfname, cfgtypes)
        for xc_info in in_device_cfgs["xConnects"]:
            _, rip = self._parse_ipaddr_dict(xc_info["remoteIp"])
            in_vni = xc_info["invxlanVni"]
            dscp = xc_info["dscp"]
            key = "%d" % (in_vni)
            in_device_xconnect_cfgs[key] = {"ivni": in_vni, "dscp": dscp}

        for item in res:
            in_vni = item["xconnectDscp"]["ivni"]
            dscp = item["xconnectDscp"]["dscp"]
            key = "%d" % (in_vni)
            value = item["xconnectDscp"]
            e_res = expect_res[key]
            if e_res != item["result"]["info"]:
                self.log_info("set xconnect dscp %s result not expected, expect %s but %s" % (
                    key, e_res, item["result"]["info"]))
                return False
            if e_res == "success":
                if key not in in_device_xconnect_cfgs:
                    self.log_info("set xconnect dscp  %s success, but not set in device" % (key))
                    return False
                if in_device_xconnect_cfgs[key] != value:
                    self.log_info("set xconnect  %s success, but %s inconsitent with %s in device" %
                                    (key, str(value), str(in_device_xconnect_cfgs[key])))
                    return False
        return True

    def _handle_xconnect(self, vrfname, xc_infos, op):
        if len(xc_infos) == 0:
            return
        dict_request = {
            "vrf": {
                "vrfName": vrfname
            },
            "xconnects": [
            ]
        }
        expect_res = {}
        for index in range(len(xc_infos)):
            xc_info = xc_infos[index]
            item = {}
            item["remoteIp"] = self._encap_ip_item(xc_info["nexthop"], "ipv4")
            item["invxlanVni"] = int(xc_info["in_vni"])
            item["outvxlanVni"] = int(xc_info["out_vni"])
            item["dscp"] = int(xc_info["dscp"])
            dict_request["xconnects"].append(item)

            expect_key = "%s-%s-%s" % (xc_info["in_vni"], xc_info["nexthop"], xc_info["out_vni"])
            if "expect_res" not in xc_info:
                xc_info["expect_res"] = "success"
            expect_res[expect_key] = xc_info["expect_res"]
            if (index + 1) % 20000 == 0:
                grpc_ret = None
                if op == "create":
                    grpc_ret = self.ntb_grpc_client.grpc_call("addCrossConnect", dict_request)
                else:
                    grpc_ret = self.ntb_grpc_client.grpc_call("delCrossConnect", dict_request)

                self.assert_("%s xconnect faild, not expected" % (op),
                            self._check_xconnect_res(vrfname, op, grpc_ret["xconnectResults"], expect_res))
                expect_res = {}
                dict_request["xconnects"].clear()
        if len(dict_request["xconnects"]) > 0:
            grpc_ret = None
            if op == "create":
                grpc_ret = self.ntb_grpc_client.grpc_call("addCrossConnect", dict_request)
            else:
                grpc_ret = self.ntb_grpc_client.grpc_call("delCrossConnect", dict_request)
            self.assert_("%s xconnect faild, not expected" % (op),
                        self._check_xconnect_res(vrfname, op, grpc_ret["xconnectResults"], expect_res))

    def _handle_xconnect_dscp_update(self, vrfname, xc_dscp_info_list):
        if len(xc_dscp_info_list) == 0:
            return
        dict_request = {
            "vrf": {
                "vrfName": vrfname
            },
            "xconnectDscps": [
            ]
        }
        expect_res = {}
        for index in range(len(xc_dscp_info_list)):
            xc_dscp_info = xc_dscp_info_list[index]
            item = {}
            item["ivni"] = int(xc_dscp_info["in_vni"])
            item["dscp"] = int(xc_dscp_info["dscp"])
            dict_request["xconnectDscps"].append(item)

            expect_key = "%d" % (int(xc_dscp_info["in_vni"]))
            if "expect_res" not in xc_dscp_info:
                xc_dscp_info["expect_res"] = "success"
            expect_res[expect_key] = xc_dscp_info["expect_res"]
            if (index + 1) % 20000 == 0:
                grpc_ret = self.ntb_grpc_client.grpc_call("setCrossConnectDscp", dict_request)
                self.assert_("set xconnect dscp faild, not expected",
                            self._check_xconnect_dscp_res(vrfname, grpc_ret["xconnectDscpResults"], expect_res))
                expect_res = {}
                dict_request["xconnectDscps"].clear()
        if len(dict_request["xconnectDscps"]) > 0:
            grpc_ret = self.ntb_grpc_client.grpc_call("setCrossConnectDscp", dict_request)
            self.assert_("set xconnect dscp faild, not expected",
                        self._check_xconnect_dscp_res(vrfname, grpc_ret["xconnectDscpResults"], expect_res))

    def create_xconnect(self, vrfname, xc_info_list):
        """
        创建vxlan路由
        :param vrfname: vrf name
        :param xc_info_list: xconnect信息列表
            item: eg: {"in_vni": 1001, "nexthop": "2.2.2.2", "out_vni": 100, "dscp": 0, "expect_res": "success"}
        :return
        """
        self._handle_xconnect(vrfname, xc_info_list, "create")

    def delete_xconnect(self, vrfname, xc_info_list):
        """
        删除vxlan路由
        :param vrfname: vrf name
        :param xc_info_list: xconnect信息列表
            item: eg: {"in_vni": 1001, "nexthop": "2.2.2.2", "out_vni": 100, "dscp": 0, "expect_res": "success"}
        :return
        """
        self._handle_xconnect(vrfname, xc_info_list, "delete")

    def set_xconnect_dscp(self, vrfname, xc_dscp_info_list):
        """
        更新xconnect dscp
        :param vrfname: vrf name
        :param xc_dscp_info_list: xconnect dsp信息列表
            item: eg: {"in_vni": 1001, "dscp": 0, "expect_res": "success"}
        :return
        """
        self._handle_xconnect_dscp_update(vrfname, xc_dscp_info_list)

    # -------------------------------setVrfRouteInterface/unsetVrfRouteInterface grpc-----------------------#
    def _check_nottl_res(self, vrfname, op, res, expect_res):
        in_device_nottl_cfgs = {}
        cfgtypes = ["routeVxlans", "mrouteVxlans"]
        in_device_cfgs = self.ntb_grpc_client.get_ntb_vrf_config(vrfname, cfgtypes)

        for rt_vxlan in in_device_cfgs["routeVxlans"]:
            _, pip, plen = self._parse_prefix_dict(rt_vxlan["base"]["prefix"])
            key = "%s/%d" % (pip, plen)
            in_device_nottl_cfgs[key] = rt_vxlan["isRtIntf"]

        for rt_vxlan in in_device_cfgs["mrouteVxlans"]:
            _, pip, plen = self._parse_prefix_dict(rt_vxlan["base"]["prefix"])
            key = "%s/%d" % (pip, plen)
            in_device_nottl_cfgs[key] = rt_vxlan["isRtIntf"]

        for item in res:
            _, pip, plen = self._parse_prefix_dict(item["rtInterfaceInfo"]["prefix"])
            key = "%s/%d" % (pip, plen)
            e_res = expect_res[key]
            if e_res != item["result"]["info"]:
                self.log_info(
                    "%s nottl %s result not expected, expect %s but %s" % (op, key, e_res, item["result"]["info"]))
                return False
            if op == "set":
                if e_res == "success":
                    if not in_device_nottl_cfgs[key]:
                        self.log_info("%s nottl %s success, but not set in device" % (op, key))
                        return False
            else:
                if e_res == "success":
                    if in_device_nottl_cfgs[key]:
                        self.log_info("%s nottl %s success, but still in device" % (op, key))
                        return False
        return True

    def _handle_nottl(self, vrfname, rt_list,mtu, op):
        """
        下发nottl配置
        """
        if len(rt_list) == 0:
            return
        dict_request = {
            "vrf": {
                "vrfName": vrfname
            },
            "rtInterfaceInfos": [
            ]
        }
        expect_res = {}
        for rt_info in rt_list:
            item = {}
            item["prefix"] = self._encap_prefix_item(rt_info["prefix"], rt_info["plen"], "ipv4")
            item["mtu"] = mtu
            if "tableId" in rt_info:
                item["tableId"] = rt_info["tableId"]
            else:
                item["tableId"] = 0
            dict_request["rtInterfaceInfos"].append(item)
            expect_key = "%s/%d" % (rt_info["prefix"], rt_info["plen"])
            if "expect_res" not in rt_info:
                rt_info["expect_res"] = "success"
            expect_res[expect_key] = rt_info["expect_res"]

        grpc_ret = None
        if op == "set":
            grpc_ret = self.ntb_grpc_client.grpc_call("setVrfRouteInterface", dict_request)
        else:
            grpc_ret = self.ntb_grpc_client.grpc_call("unsetVrfRouteInterface", dict_request)

        self.assert_("%s nottl faild, not expected" % (op),
                     self._check_nottl_res(vrfname, op, grpc_ret["rtInterfaceCfgs"], expect_res))

    def set_nottl(self, vrfname, rt_list,mtu=0):
        """
        设置nottl
        :param vrfname: vrf name
        :param rt_list: 路由前缀列表
            item: eg: {"prefix": "1.1.1.1", "plen": 32, "rt_table" : 1, "expect_res": "success"}
        :return
        """
        self._handle_nottl(vrfname, rt_list,mtu, "set")

    def unset_nottl(self, vrfname, rt_list,mtu=0):
        """
        取消nottl
        :param vrfname: vrf name
        :param rt_list: 路由前缀列表
            item: eg: {"prefix": "1.1.1.1", "plen": 32, "rt_table" : 1, "expect_res": "success"}
        :return
        """
        self._handle_nottl(vrfname, rt_list,mtu, "unset")

    # -------------------------------transToVrfMRoute/transToVrfRoute grpc-----------------------#
    def _get_vrf_config_in_device(self, vrfname):
        """
        获取设备上指定vrf的配置信息
        :param vrfname: vrf name
        :return vrf_cfg_in_device map
            vrf_cfg_in_device["routeVxlans"]: vxlan路由配置
                key: eg: 1.1.1.1/32
                value: eg: {"nottl":False, "nhops":{"2.2.2.2-1001": rt_item}
            vrf_cfg_in_device["mrouteVxlans"]: mroute路由配置
                key: eg: 1.1.1.1/32
                value: eg: {"nottl":False, "nhops":{"2.2.2.2-1001": rt_item}
        """
        vrf_cfg_in_device = {}

        vrf_cfg_in_device["routeVxlans"] = {}
        vrf_cfg_in_device["mrouteVxlans"] = {}
        cfgtypes = []
        in_device_cfgs = self.ntb_grpc_client.get_ntb_vrf_config(vrfname, cfgtypes)
        for rt_vxlan in in_device_cfgs["routeVxlans"]:
            _, pip, plen = self._parse_prefix_dict(rt_vxlan["base"]["prefix"])
            _, nip = self._parse_ipaddr_dict(rt_vxlan["base"]["nexthopIp"])
            vni = rt_vxlan["base"]["vni"]
            p_key = "%s/%d" % (pip, plen)
            if p_key not in vrf_cfg_in_device["routeVxlans"]:
                vrf_cfg_in_device["routeVxlans"][p_key] = {}
                vrf_cfg_in_device["routeVxlans"][p_key]["nhops"] = {}
            r_key = "%s-%d" % (nip, vni)
            vrf_cfg_in_device["routeVxlans"][p_key]["nhops"][r_key] = rt_vxlan["base"]
            vrf_cfg_in_device["routeVxlans"][p_key]["nottl"] = rt_vxlan["isRtIntf"]

        for rt_vxlan in in_device_cfgs["mrouteVxlans"]:
            _, pip, plen = self._parse_prefix_dict(rt_vxlan["base"]["prefix"])
            _, nip = self._parse_ipaddr_dict(rt_vxlan["base"]["nexthopIp"])
            vni = rt_vxlan["base"]["vni"]
            p_key = "%s/%d" % (pip, plen)
            if p_key not in vrf_cfg_in_device["mrouteVxlans"]:
                vrf_cfg_in_device["mrouteVxlans"][p_key] = {}
                vrf_cfg_in_device["mrouteVxlans"][p_key]["nhops"] = {}
            r_key = "%s-%d" % (nip, vni)
            vrf_cfg_in_device["mrouteVxlans"][p_key]["nhops"][r_key] = rt_vxlan["base"]
            vrf_cfg_in_device["mrouteVxlans"][p_key]["nottl"] = rt_vxlan["isRtIntf"]

        return vrf_cfg_in_device

    def _check_route_trans_res(self, vrfname, op, res, expect_res, cfg_before_trans_in_device):
        cfg_after_trans_in_device = self._get_vrf_config_in_device(vrfname)

        for item in res:
            _, pip, plen = self._parse_prefix_dict(item["prefix"]["route"])
            key = "%s/%d" % (pip, plen)
            e_res = expect_res[key]
            if e_res != item["result"]["info"]:
                self.log_info(
                    "trans_%s %s result not expected, expect %s but %s" % (op, key, e_res, item["result"]["info"]))
                return False
            if op == "to_mroute":
                if e_res == "success":
                    if key not in cfg_after_trans_in_device["mrouteVxlans"]:
                        self.log_info("trans_%s %s success, but device not" % (op, key))
                        return False
                    nhops = cfg_after_trans_in_device["mrouteVxlans"][key]["nhops"]
                    for nhop_key in list(nhops.keys()):
                        if nhops[nhop_key]["weight"] == 0:
                            nhops[nhop_key]["weight"] = 2
                    if key in cfg_before_trans_in_device["routeVxlans"] and \
                            cfg_before_trans_in_device["routeVxlans"][key] != cfg_after_trans_in_device["mrouteVxlans"][key]:
                        pass
                        '''
                        self.log_info("trans_%s %s success, but trans before %s inconsitent with after %s" %
                                      (op, key, str(cfg_before_trans_in_device["routeVxlans"][key]),
                                       cfg_after_trans_in_device["mrouteVxlans"][key]))
                        '''
            else:
                if e_res == "success":
                    if key not in cfg_after_trans_in_device["routeVxlans"]:
                        self.log_info("trans_%s %s success, but device not" % (op, key))
                        return False
                    nhops = cfg_after_trans_in_device["routeVxlans"][key]["nhops"]
                    for nhop_key in list(nhops.keys()):
                        if nhops[nhop_key]["weight"] == 0:
                            nhops[nhop_key]["weight"] = 2
                    if key in cfg_before_trans_in_device["mrouteVxlans"] and \
                            cfg_before_trans_in_device["mrouteVxlans"][key] != cfg_after_trans_in_device["routeVxlans"][key]:
                        pass
                        '''
                        self.log_info("trans_%s %s success, but trans before %s inconsitent with after %s" %
                                      (op, key, str(cfg_before_trans_in_device["mrouteVxlans"][key]),
                                       cfg_after_trans_in_device["routeVxlans"][key]))
                        '''
        return True

    def _handle_route_trans(self, vrfname, rt_list, op):
        """
        route与mroute互转
        """
        if len(rt_list) == 0:
            return
        dict_request = {
            "prefixes": [
            ]
        }
        # 获取转换之前的路由配置
        cfg_before_trans_in_device = self._get_vrf_config_in_device(vrfname)

        # 调用trans接口
        expect_res = {}
        for rt_info in rt_list:
            item = {}
            if "prefix" in rt_info:
                item["route"] = self._encap_prefix_item(rt_info["prefix"], rt_info["plen"], "ipv4")
            else:
                rt_info["prefix"] = "0.0.0.0"
                rt_info["plen"] = 0
                item["route"] = self._encap_prefix_item(rt_info["prefix"], rt_info["plen"], "ipv4")
            item["vrf"] = {}
            item["vrf"]["vrfName"] = vrfname
            dict_request["prefixes"].append(item)
            expect_key = "%s/%d" % (rt_info["prefix"], rt_info["plen"])
            if "expect_res" not in rt_info:
                rt_info["expect_res"] = "success"
            expect_res[expect_key] = rt_info["expect_res"]

        grpc_ret = None
        if op == "to_mroute":
            grpc_ret = self.ntb_grpc_client.grpc_call("transToVrfMRoute", dict_request)
        else:
            grpc_ret = self.ntb_grpc_client.grpc_call("transToVrfRoute", dict_request)

        self.assert_("trans_%s faild, not expected" % (op),
                     self._check_route_trans_res(vrfname, op, grpc_ret["prefixResults"], expect_res,
                                                 cfg_before_trans_in_device))

    def trans_to_mroute(self, vrfname, rt_list):
        """
        将普通路由转换成mroute
        :param vrfname: vrf name
        :param rt_list: 路由前缀列表
            item: eg: {"prefix": "1.1.1.1", "plen": 32, "expect_res": "success"}
        :return
        """
        self._handle_route_trans(vrfname, rt_list, "to_mroute")

    def trans_to_route(self, vrfname, rt_list):
        """
        将mroute路由转换成普通路由
        :param vrfname: vrf name
        :param rt_list: 路由前缀列表
            item: eg: {"prefix": "1.1.1.1", "plen": 32, "expect_res": "success"}
        :return
        """
        self._handle_route_trans(vrfname, rt_list, "to_route")

    # -------------------------------addBlackholeRoute/delBlackholeRoute grpc-----------------------#
    def _check_blackhole_route_res(self, vrfname, op, res, expect_res):

        in_device_bh_route_cfgs = {}
        cfgtypes = ["bhRoutes"]
        in_device_cfgs = self.ntb_grpc_client.get_ntb_vrf_config(vrfname, cfgtypes)
        for rt in in_device_cfgs["bhRoutes"]:
            _, pip, plen = self._parse_prefix_dict(rt["prefix"])
            key = "%s/%d-%d" % (pip, plen, rt['tableId'])
            in_device_bh_route_cfgs[key] = rt

        for item in res:
            _, pip, plen = self._parse_prefix_dict(item["bhroute"]["prefix"])
            key = "%s/%d-%d" % (pip, plen, item["bhroute"]["tableId"])
            value = item["bhroute"]
            e_res = expect_res[key]
            if e_res != item["result"]["info"]:
                self.log_info("%s blackhole route %s result not expected, expect %s but %s" % (
                    op, key, e_res, item["result"]["info"]))
                return False
            if op == "create":
                if e_res == "success":
                    if key not in in_device_bh_route_cfgs:
                        self.log_info("%s blackhole route  %s success, but not set in device" % (op, key))
                        return False
                    if in_device_bh_route_cfgs[key] != value:
                        self.log_info("%s blackhole route  %s success, but %s inconsitent with %s in device" %
                                      (op, key, str(value), str(in_device_bh_route_cfgs[key])))
                        return False
            else:
                if e_res == "success":
                    if key in in_device_bh_route_cfgs:
                        self.log_info("%s blackhole route  %s success, but still in device" % (op, key))
                        return False
        return True

    def _handle_blackhole_route(self, vrfname, blackhole_info_list, op, check=True):
        """
        下发黑洞路由配置
        """
        if len(blackhole_info_list) == 0:
            return
        dict_request = {
            "vrf": {
                "vrfName": vrfname
            },
            "bhRoutes": [
            ]
        }
        expect_res = {}
        for index in range(len(blackhole_info_list)):
            blackhole_info = blackhole_info_list[index]
            item = {}
            if "prefix" in blackhole_info:
                item["prefix"] = self._encap_prefix_item(blackhole_info["prefix"], blackhole_info["plen"], "ipv4")
            else:
                blackhole_info["prefix"] = "0.0.0.0"
                blackhole_info["plen"] = 0
                item["prefix"] = self._encap_prefix_item(blackhole_info["prefix"], blackhole_info["plen"], "ipv4")

            if "rt_table" not in  blackhole_info:
                item["tableId"] = 0
                blackhole_info["rt_table"] = 0
            else:
                item["tableId"] = blackhole_info["rt_table"]

            dict_request["bhRoutes"].append(item)
            expect_key = "%s/%d-%d" % (
                blackhole_info["prefix"], blackhole_info["plen"], blackhole_info["rt_table"])
            if "expect_res" not in blackhole_info:
                blackhole_info["expect_res"] = "success"
            expect_res[expect_key] = blackhole_info["expect_res"]
            if (index + 1) % 20000 == 0:
                grpc_ret = None
                if op == "create":
                    grpc_ret = self.ntb_grpc_client.grpc_call("addBlackholeRoute", dict_request)
                else:
                    grpc_ret = self.ntb_grpc_client.grpc_call("delBlackholeRoute", dict_request)

                if check:
                    self.assert_("%s blackhole faild, not expected" % (op),
                                self._check_blackhole_route_res(vrfname, op, grpc_ret["bhRouteCfgResults"], expect_res))
                else:
                    self.assert_("%s blackhole faild, not expected" % (op),
                                grpc_ret["result"]["info"] == "success")
                expect_res = {}
                dict_request["bhRoutes"].clear()
        if len(dict_request["bhRoutes"]) > 0:
            grpc_ret = None
            if op == "create":
                grpc_ret = self.ntb_grpc_client.grpc_call("addBlackholeRoute", dict_request)
            else:
                grpc_ret = self.ntb_grpc_client.grpc_call("delBlackholeRoute", dict_request)
            if check:
                self.assert_("%s blackhole faild, not expected" % (op),
                            self._check_blackhole_route_res(vrfname, op, grpc_ret["bhRouteCfgResults"], expect_res))
            else:
                self.assert_("%s blackhole faild, not expected" % (op),
                            grpc_ret["result"]["info"] == "success")

    def create_blackhole_route(self, vrfname, blackhole_info_list, check=True):
        """
        创建黑洞路由
        :param vrfname: vrf name
        :param blackhole_info_list: 黑洞路由信息列表
            item: eg: {"prefix": "1.1.1.1", "plen": 32, "rt_table": 1, "expect_res": "success"}
        :return
        """
        self._handle_blackhole_route(vrfname, blackhole_info_list, "create", check)

    def delete_blackhole_route(self, vrfname, blackhole_info_list, check=True):
        """
        删除黑洞路由
        :param vrfname: vrf name
        :param blackhole_info_list: 黑洞路由信息列表
            item: eg: {"prefix": "1.1.1.1", "plen": 32, "rt_table": 1, "expect_res": "success"}
        :return
        """
        self._handle_blackhole_route(vrfname, blackhole_info_list, "delete", check)


    # -------------------------------addVrfRouteVxLan/delVrfRouteVxLan grpc-----------------------#
    def check_vxlan_route_count(self, vrfname, expect_res, tableid=0):
        """
        检查VXLAN路由在设备中的实际数量是否符合预期
        """
        in_device_vxlan_route_cfgs = {}
        in_device_vxlan_route_prefixs = {}

        cfgtypes = ["routeVxlans"]
        in_device_cfgs = self.ntb_grpc_client.get_ntb_vrf_config(vrfname, cfgtypes)
        for rt_vxlan in in_device_cfgs["routeVxlans"]:
            _, pip, plen = self._parse_prefix_dict(rt_vxlan["base"]["prefix"])
            _, nip = self._parse_ipaddr_dict(rt_vxlan["base"]["nexthopIp"])
            if "gateway" not in rt_vxlan["base"]:
                gateway = "0.0.0.0"
            else:
                _, gateway = self._parse_ipaddr_dict(rt_vxlan["base"]["gateway"])

            if "tableId" not in rt_vxlan["base"]:
                tableId = 0
            else:
                tableId = rt_vxlan["base"]["tableId"]

            vni = rt_vxlan["base"]["vni"]
            key = "%s/%d-%d-%s-%d-%s" % (pip, plen, tableId, nip, vni, gateway)

            prefixkey = "%s/%d-%d" % (pip, plen, tableId)
            in_device_vxlan_route_cfgs[key] = rt_vxlan["base"]
            if prefixkey in in_device_vxlan_route_prefixs:
                in_device_vxlan_route_prefixs[prefixkey] = in_device_vxlan_route_prefixs[prefixkey] + 1
            else:
                in_device_vxlan_route_prefixs[prefixkey] = 1

        for prefixkey, value in expect_res.items():
            prefixkey = prefixkey + "-%d" % tableid
            if prefixkey not in in_device_vxlan_route_prefixs:
                if value != 0:
                    self.assert_("vxlan route prefix %s rpath count not expected, expect %d but 0" %
                            (prefixkey, value), False)
                continue

            if value != in_device_vxlan_route_prefixs[prefixkey]:
                self.assert_("vxlan route prefix %s rpath count not expected, expect %d but %d" %
                        (prefixkey, value, in_device_vxlan_route_prefixs[prefixkey]), False)

    def _check_vxlan_route_res(self, vrfname, op, res, expect_res):

        in_device_vxlan_route_cfgs = {}
        in_device_vxlan_route_prefixs = {}
        cfgtypes = ["routeVxlans"]
        in_device_cfgs = self.ntb_grpc_client.get_ntb_vrf_config(vrfname, cfgtypes)
        for rt_vxlan in in_device_cfgs["routeVxlans"]:
            pfamily, pip, plen = self._parse_prefix_dict(rt_vxlan["base"]["prefix"])
            _, nip = self._parse_ipaddr_dict(rt_vxlan["base"]["nexthopIp"])
            if "gateway" not in rt_vxlan["base"]:
                if pfamily == 2:
                    gateway = "::"
                else:
                    gateway = "0.0.0.0"
            else:
                _, gateway = self._parse_ipaddr_dict(rt_vxlan["base"]["gateway"])

            if "tableId" not in rt_vxlan["base"]:
                tableId = 0
            else:
                tableId = rt_vxlan["base"]["tableId"]
            vni = rt_vxlan["base"]["vni"]
            key = "%s/%d-%d-%s-%d-%s" % (pip, plen, tableId, nip, vni, gateway)

            prefixkey = "%s/%d-%d" % (pip, plen, tableId)
            in_device_vxlan_route_cfgs[key] = rt_vxlan["base"]
            if prefixkey in in_device_vxlan_route_prefixs:
                in_device_vxlan_route_prefixs[prefixkey] = in_device_vxlan_route_prefixs[prefixkey] + 1
            else:
                in_device_vxlan_route_prefixs[prefixkey] = 1

        for item in res:
            if "prefix" in item["rtvxlan"]:
                pfamily, pip, plen = self._parse_prefix_dict(item["rtvxlan"]["prefix"])
            else:
                pfamily = 1
                pip = "0.0.0.0"
                plen = 0
                item["rtvxlan"]["prefix"] = self._encap_prefix_item(pip, plen, "ipv4")

            if "nexthopIp" in item["rtvxlan"]:
                _, nip = self._parse_ipaddr_dict(item["rtvxlan"]["nexthopIp"])
            else:
                nip = "0.0.0.0"
                item["rtvxlan"]["nexthopIp"] = self._encap_ip_item(nip, "ipv4")

            if "vni" in item["rtvxlan"]:
                vni = item["rtvxlan"]["vni"]
            else:
                vni = 0
                item["rtvxlan"]["vni"] = vni

            if "gateway" not in item["rtvxlan"]:
                if pfamily == 2:
                    gateway = "::"
                else:
                    gateway = "0.0.0.0"
                item["rtvxlan"]["gateway"] = self._encap_ip_item(gateway, "ipv4")
            else:
                _, gateway = self._parse_ipaddr_dict(item["rtvxlan"]["gateway"])

            if "tableId" not in item["rtvxlan"]:
                tableId = 0
                item["rtvxlan"]["tableId"] = tableId
            else:
                tableId = item["rtvxlan"]["tableId"]

            if "dscp" not in item["rtvxlan"]:
                dscp = 0
                item["rtvxlan"]["dscp"] = 0
            else:
                dscp = item["rtvxlan"]["dscp"]

            key = "%s/%d-%d-%s-%d-%s" % (pip, plen, tableId, nip, vni, gateway)
            prefixkey = "%s/%d-%d" % (pip, plen, tableId)
            value = item["rtvxlan"]

            if "weight" in value and value['weight'] == 0:
                value["weight"] = 2

            e_res = expect_res[key]
            if e_res != item["result"]["info"]:
                self.log_info("%s vxlan route %s result not expected, expect %s but %s" % (
                    op, key, e_res, item["result"]["info"]))
                return False
            if op == "create":
                if e_res == "success":
                    if key not in in_device_vxlan_route_cfgs:
                        self.log_info("%s vxlan route  %s success, but not set in device" % (op, key))
                        return False
                    if in_device_vxlan_route_cfgs[key] != value:
                        self.log_info("%s vxlan route  %s success, but %s inconsitent with %s in device" %
                                      (op, key, str(value), str(in_device_vxlan_route_cfgs[key])))
                        return False
            else:
                if e_res == "success":
                    if nip == "0.0.0.0" and prefixkey in in_device_vxlan_route_prefixs:
                        self.log_info("%s vxlan route  %s success, but prefix %s still in device" % (op, key, prefixkey))
                        return False

                    if key in in_device_vxlan_route_cfgs:
                        self.log_info("%s vxlan route  %s success, but still in device" % (op, key))
                        return False
        return True

    def _handle_vxlan_route(self, vrfname, vxlan_infos, op, check=True, expect_grpc_ret="success"):
        """
        下发vxlan路由配置
        """
        if len(vxlan_infos) == 0:
            return
        dict_request = {
            "vrf": {
                "vrfName": vrfname
            },
            "rtVxlans": [
            ]
        }
        expect_res = {}
        for index in range(len(vxlan_infos)):
            vxlan_info = vxlan_infos[index]
            item = {}
            if "prefix" in vxlan_info:
                item["prefix"] = self._encap_prefix_item(vxlan_info["prefix"], vxlan_info["plen"], "ipv4")
            else:
                vxlan_info["prefix"] = "0.0.0.0"
                vxlan_info["plen"] = 0

            if "nexthop" in vxlan_info:
                item["nexthopIp"] = self._encap_ip_item(vxlan_info["nexthop"], "ipv4")
            else:
                vxlan_info["nexthop"] = "0.0.0.0"

            if "vni" in vxlan_info:
                item["vni"] = vxlan_info["vni"]
            else:
                vxlan_info["vni"] = 0

            item["vni"] = vxlan_info["vni"]

            if "dscp" in vxlan_info:
                item["dscp"] = vxlan_info["dscp"]
            else:
                item["dscp"] = 0

            if "weight" in vxlan_info:
                item["weight"] = vxlan_info["weight"]
            else:
                item["weight"] = 0

            if "gateway" not in vxlan_info:
                if "prefix" in item and item["prefix"]["family"] == 2:
                    vxlan_info["gateway"] = "::"
                else:
                    vxlan_info["gateway"] = "0.0.0.0"

            item["gateway"] = self._encap_ip_item(vxlan_info["gateway"], "ipv4")
            if "rt_table" not in  vxlan_info:
                item["tableId"] = 0
                vxlan_info["rt_table"] = 0
            else:
                item["tableId"] = vxlan_info["rt_table"]

            dict_request["rtVxlans"].append(item)
            expect_key = "%s/%d-%d-%s-%d-%s" % (
                vxlan_info["prefix"], vxlan_info["plen"], vxlan_info["rt_table"], vxlan_info["nexthop"], vxlan_info["vni"], vxlan_info["gateway"])
            if "expect_res" not in vxlan_info:
                vxlan_info["expect_res"] = "success"
            expect_res[expect_key] = vxlan_info["expect_res"]

            if (index + 1) % 20000 == 0:
                grpc_ret = None
                if op == "create":
                    grpc_ret = self.ntb_grpc_client.grpc_call("addVrfRouteVxLan", dict_request)
                else:
                    grpc_ret = self.ntb_grpc_client.grpc_call("delVrfRouteVxLan", dict_request)

                if check:
                    self.assert_("%s vxlan route faild, not expected" % (op),
                                self._check_vxlan_route_res(vrfname, op, grpc_ret["rtVxlanCfgResults"], expect_res))
                    if expect_grpc_ret != "success":
                        self.assert_("%s vxlan route %s, not expected" % (op, grpc_ret["result"]["info"]),
                                    grpc_ret["result"]["info"] == expect_grpc_ret)
                else:
                    self.assert_("%s vxlan route %s, not expected" % (op, grpc_ret["result"]["info"]),
                                grpc_ret["result"]["info"] == expect_grpc_ret)
                expect_res = {}
                dict_request["rtVxlans"].clear()

        if len(dict_request["rtVxlans"]) > 0:
            grpc_ret = None
            if op == "create":
                grpc_ret = self.ntb_grpc_client.grpc_call("addVrfRouteVxLan", dict_request)
            else:
                grpc_ret = self.ntb_grpc_client.grpc_call("delVrfRouteVxLan", dict_request)
            if check:
                self.assert_("%s vxlan route faild, not expected" % (op),
                            self._check_vxlan_route_res(vrfname, op, grpc_ret["rtVxlanCfgResults"], expect_res))
                if expect_grpc_ret != "success":
                    self.assert_("%s vxlan route %s, not expected" % (op, grpc_ret["result"]["info"]),
                                grpc_ret["result"]["info"] == expect_grpc_ret)
            else:
                self.assert_("%s vxlan route %s, not expected" % (op, grpc_ret["result"]["info"]),
                            grpc_ret["result"]["info"] == expect_grpc_ret)

    def create_vxlan_route(self, vrfname, vxlan_info_list, check=True):
        """
        创建vxlan路由
        :param vrfname: vrf name
        :param vxlan_info_list: vxlan路由信息列表
            item: eg: {"prefix": "1.1.1.1", "plen": 32, "nexthop": "2.2.2.2", "vni": 100, "gateway": "0.0.0.0", "rt_table": 1,  weight: 2, "expect_res": "success"}
        :return
        """
        self._handle_vxlan_route(vrfname, vxlan_info_list, "create", check)

    def delete_vxlan_route(self, vrfname, vxlan_info_list, check=True):
        """
        删除vxlan路由
        :param vrfname: vrf name
        :param vxlan_info_list: vxlan路由信息列表
            item: eg: {"prefix": "1.1.1.1", "plen": 32, "nexthop": "2.2.2.2", "vni": 100, "gateway": "0.0.0.0", "rt_table": 1, weight: 2, "expect_res": "success"}
        :return
        """
        self._handle_vxlan_route(vrfname, vxlan_info_list, "delete", check)

    def create_vxlan_route_with_fail(self, vrfname, vxlan_info_list, check=True, expect_grpc_ret="failure"):
        """
        创建vxlan路由
        :param vrfname: vrf name
        :param vxlan_info_list: vxlan路由信息列表
            item: eg: {"prefix": "1.1.1.1", "plen": 32, "nexthop": "2.2.2.2", "vni": 100, "gateway": "0.0.0.0", "rt_table": 1,  weight: 2, "expect_res": "success"}
        :param expect_grpc_ret: expected grpc return value
        :return
        """
        self._handle_vxlan_route(vrfname, vxlan_info_list, "create", check, expect_grpc_ret)

    def _check_vxlan_route_status(self, vrfname, vxlan_info_list, exist):
        in_device_vxlan_route_cfgs = {}
        cfgtypes = ["routeVxlans"]
        in_device_cfgs = self.ntb_grpc_client.get_ntb_vrf_config(vrfname, cfgtypes)
        for rt_vxlan in in_device_cfgs["routeVxlans"]:
            _, pip, plen = self._parse_prefix_dict(rt_vxlan["base"]["prefix"])
            _, nip = self._parse_ipaddr_dict(rt_vxlan["base"]["nexthopIp"])
            vni = rt_vxlan["base"]["vni"]
            key = "%s/%d-%s-%d" % (pip, plen, nip, vni)
            in_device_vxlan_route_cfgs[key] = rt_vxlan["base"]

        for vxlan_info in vxlan_info_list:
            key = "%s/%d-%s-%d" % (vxlan_info["prefix"], vxlan_info["plen"], vxlan_info["nexthop"], vxlan_info["vni"])
            if exist:
                if key not in in_device_vxlan_route_cfgs:
                    self.assert_("%s vxlan route not exist" % (key), False)
            else:
                if key in in_device_vxlan_route_cfgs:
                    self.assert_("%s vxlan route exist" % (key), False)

    def check_vxlan_route_exist(self, vrfname, vxlan_info_list):
        """
        检查路由信息是否存在
        :param vrfname: vrf name
        :param vxlan_info_list: vxlan路由信息列表
            item: eg: {"prefix": "1.1.1.1", "plen": 32, "nexthop": "2.2.2.2", "vni": 100, "gateway": "0.0.0.0", "rt_table": 1, weight: 2, "expect_res": "success"}
        :return
        """
        self._check_vxlan_route_status(vrfname, vxlan_info_list, True)

    def check_vxlan_route_not_exist(self, vrfname, vxlan_info_list):
        """
        检查路由信息是否不存在
        :param vrfname: vrf name
        :param vxlan_info_list: vxlan路由信息列表
            item: eg: {"prefix": "1.1.1.1", "plen": 32, "nexthop": "2.2.2.2", "vni": 100, "gateway": "0.0.0.0", "rt_table": 1, weight: 2, "expect_res": "success"}
        :return
        """
        self._check_vxlan_route_status(vrfname, vxlan_info_list, False)

    # -------------------------------addVrfMRouteVxLan/delVrfMRouteVxLan grpc-----------------------#
    def check_vxlan_mroute_count(self, vrfname, expect_res, tableid=0):
        """
        检查VXLAN组播路由在设备中的实际数量是否符合预期
        """
        in_device_vxlan_route_cfgs = {}
        in_device_vxlan_route_prefixs = {}

        cfgtypes = ["mrouteVxlans"]
        in_device_cfgs = self.ntb_grpc_client.get_ntb_vrf_config(vrfname, cfgtypes)
        for rt_vxlan in in_device_cfgs["mrouteVxlans"]:
            _, pip, plen = self._parse_prefix_dict(rt_vxlan["base"]["prefix"])
            _, nip = self._parse_ipaddr_dict(rt_vxlan["base"]["nexthopIp"])
            if "gateway" not in rt_vxlan["base"]:
                gateway = "0.0.0.0"
            else:
                _, gateway = self._parse_ipaddr_dict(rt_vxlan["base"]["gateway"])

            if "tableId" not in rt_vxlan["base"]:
                tableId = 0
            else:
                tableId = rt_vxlan["base"]["tableId"]

            vni = rt_vxlan["base"]["vni"]
            key = "%s/%d-%d-%s-%d-%s" % (pip, plen, tableId, nip, vni, gateway)

            prefixkey = "%s/%d-%d" % (pip, plen, tableId)
            in_device_vxlan_route_cfgs[key] = rt_vxlan["base"]
            if prefixkey in in_device_vxlan_route_prefixs:
                in_device_vxlan_route_prefixs[prefixkey] = in_device_vxlan_route_prefixs[prefixkey] + 1
            else:
                in_device_vxlan_route_prefixs[prefixkey] = 1

        for prefixkey, value in expect_res.items():
            prefixkey = prefixkey + "-%d" % tableid
            if prefixkey not in in_device_vxlan_route_prefixs:
                if value != 0:
                    self.assert_("vxlan route prefix %s rpath count not expected, expect %d but 0" %
                            (prefixkey, value), False)
                continue

            if value != in_device_vxlan_route_prefixs[prefixkey]:
                self.assert_("vxlan route prefix %s rpath count not expected, expect %d but %d" %
                        (prefixkey, value, in_device_vxlan_route_prefixs[prefixkey]), False)

    def _check_vxlan_mroute_res(self, vrfname, op, res, expect_res):

        in_device_vxlan_route_cfgs = {}
        in_device_vxlan_route_prefixs = {}
        cfgtypes = ["mrouteVxlans"]
        in_device_cfgs = self.ntb_grpc_client.get_ntb_vrf_config(vrfname, cfgtypes)
        for rt_vxlan in in_device_cfgs["mrouteVxlans"]:
            pfamily, pip, plen = self._parse_prefix_dict(rt_vxlan["base"]["prefix"])
            _, nip = self._parse_ipaddr_dict(rt_vxlan["base"]["nexthopIp"])
            if "gateway" not in rt_vxlan["base"]:
                if pfamily == 2:
                    gateway = "::"
                else:
                    gateway = "0.0.0.0"
            else:
                _, gateway = self._parse_ipaddr_dict(rt_vxlan["base"]["gateway"])

            if "tableId" not in rt_vxlan["base"]:
                tableId = 0
            else:
                tableId = rt_vxlan["base"]["tableId"]
            vni = rt_vxlan["base"]["vni"]
            key = "%s/%d-%d-%s-%d-%s" % (pip, plen, tableId, nip, vni, gateway)

            prefixkey = "%s/%d-%d" % (pip, plen, tableId)
            in_device_vxlan_route_cfgs[key] = rt_vxlan["base"]
            if prefixkey in in_device_vxlan_route_prefixs:
                in_device_vxlan_route_prefixs[prefixkey] = in_device_vxlan_route_prefixs[prefixkey] + 1
            else:
                in_device_vxlan_route_prefixs[prefixkey] = 1

        for item in res:
            if "prefix" in item["rtvxlan"]:
                pfamily, pip, plen = self._parse_prefix_dict(item["rtvxlan"]["prefix"])
            else:
                pfamily = 1
                pip = "0.0.0.0"
                plen = 0
                item["rtvxlan"]["prefix"] = self._encap_prefix_item(pip, plen, "ipv4")

            if "nexthopIp" in item["rtvxlan"]:
                _, nip = self._parse_ipaddr_dict(item["rtvxlan"]["nexthopIp"])
            else:
                nip = "0.0.0.0"
                item["rtvxlan"]["nexthopIp"] = self._encap_ip_item(nip, "ipv4")

            if "vni" in item["rtvxlan"]:
                vni = item["rtvxlan"]["vni"]
            else:
                vni = 0
                item["rtvxlan"]["vni"] = vni

            if "gateway" not in item["rtvxlan"]:
                if pfamily == 2:
                    gateway = "::"
                else:
                    gateway = "0.0.0.0"
                item["rtvxlan"]["gateway"] = self._encap_ip_item(gateway, "ipv4")
            else:
                _, gateway = self._parse_ipaddr_dict(item["rtvxlan"]["gateway"])

            if "tableId" not in item["rtvxlan"]:
                tableId = 0
                item["rtvxlan"]["tableId"] = tableId
            else:
                tableId = item["rtvxlan"]["tableId"]

            if "dscp" not in item["rtvxlan"]:
                tableId = 0
                item["rtvxlan"]["tableId"] = tableId
            else:
                tableId = item["rtvxlan"]["tableId"]

            key = "%s/%d-%d-%s-%d-%s" % (pip, plen, tableId, nip, vni, gateway)
            prefixkey = "%s/%d-%d" % (pip, plen, tableId)
            value = item["rtvxlan"]

            e_res = expect_res[key]
            if e_res != item["result"]["info"]:
                self.log_info("%s vxlan mroute %s result not expected, expect %s but %s" % (
                    op, key, e_res, item["result"]["info"]))
                return False
            if op == "create":
                if e_res == "success":
                    if key not in in_device_vxlan_route_cfgs:
                        self.log_info("%s vxlan mroute  %s success, but not set in device" % (op, key))
                        return False
                    
                    # mroute 配置核查不显示weight
                    if "weight" in value:
                        value_copy = value.copy()  # 创建value的副本
                        value_copy['weight'] = 0   # 在副本上修改weight
                    else:
                        value_copy = value
                    if in_device_vxlan_route_cfgs[key] != value_copy:
                        self.log_info("%s vxlan mroute  %s success, but %s inconsitent with %s in device" %
                                      (op, key, str(value_copy), str(in_device_vxlan_route_cfgs[key])))
                        return False
            else:
                if e_res == "success":
                    if nip == "0.0.0.0" and prefixkey in in_device_vxlan_route_prefixs:
                        self.log_info("%s vxlan mroute  %s success, but prefix %s still in device" % (op, key, prefixkey))
                        return False

                    if key in in_device_vxlan_route_cfgs:
                        self.log_info("%s vxlan mroute  %s success, but still in device" % (op, key))
                        return False
        return True

    def _handle_vxlan_mroute(self, vrfname, vxlan_infos, op, check=True):
        """
        下发vxlan mroute路由配置
        """
        if len(vxlan_infos) == 0:
            return
        dict_request = {
            "vrf": {
                "vrfName": vrfname
            },
            "rtVxlans": [
            ]
        }
        expect_res = {}
        for index in range(len(vxlan_infos)):
            vxlan_info = vxlan_infos[index]
            item = {}
            if "prefix" in vxlan_info:
                item["prefix"] = self._encap_prefix_item(vxlan_info["prefix"], vxlan_info["plen"], "ipv4")
            else:
                vxlan_info["prefix"] = "0.0.0.0"
                vxlan_info["plen"] = 0

            if "nexthop" in vxlan_info:
                item["nexthopIp"] = self._encap_ip_item(vxlan_info["nexthop"], "ipv4")
            else:
                vxlan_info["nexthop"] = "0.0.0.0"

            if "vni" in vxlan_info:
                item["vni"] = vxlan_info["vni"]
            else:
                vxlan_info["vni"] = 0

            item["vni"] = vxlan_info["vni"]

            if "dscp" in vxlan_info:
                item["dscp"] = vxlan_info["dscp"]
            else:
                item["dscp"] = 0

            if "weight" in vxlan_info:
                item["weight"] = vxlan_info["weight"]
            else:
                item["weight"] = 0

            if "gateway" not in vxlan_info:
                if "prefix" in item and item["prefix"]["family"] == 2:
                    vxlan_info["gateway"] = "::"
                else:
                    vxlan_info["gateway"] = "0.0.0.0"

            item["gateway"] = self._encap_ip_item(vxlan_info["gateway"], "ipv4")
            if "rt_table" not in  vxlan_info:
                item["tableId"] = 0
                vxlan_info["rt_table"] = 0
            else:
                item["tableId"] = vxlan_info["rt_table"]

            dict_request["rtVxlans"].append(item)
            expect_key = "%s/%d-%d-%s-%d-%s" % (
                vxlan_info["prefix"], vxlan_info["plen"], vxlan_info["rt_table"], vxlan_info["nexthop"], vxlan_info["vni"], vxlan_info["gateway"])
            if "expect_res" not in vxlan_info:
                vxlan_info["expect_res"] = "success"
            expect_res[expect_key] = vxlan_info["expect_res"]

            if (index + 1) % 20000 == 0:
                grpc_ret = None
                if op == "create":
                    grpc_ret = self.ntb_grpc_client.grpc_call("addVrfMRouteVxLan", dict_request)
                else:
                    grpc_ret = self.ntb_grpc_client.grpc_call("delVrfMRouteVxLan", dict_request)

                if check:
                    self.assert_("%s vxlan mroute faild, not expected" % (op),
                                self._check_vxlan_mroute_res(vrfname, op, grpc_ret["rtVxlanCfgResults"], expect_res))
                else:
                    self.assert_("%s vxlan mroute faild, not expected" % (op),
                                grpc_ret["result"]["info"] == "success")
                expect_res = {}
                dict_request["rtVxlans"].clear()
        if len(dict_request["rtVxlans"]) > 0:
            grpc_ret = None
            if op == "create":
                grpc_ret = self.ntb_grpc_client.grpc_call("addVrfMRouteVxLan", dict_request)
            else:
                grpc_ret = self.ntb_grpc_client.grpc_call("delVrfMRouteVxLan", dict_request)
            if check:
                self.assert_("%s vxlan mroute faild, not expected" % (op),
                            self._check_vxlan_mroute_res(vrfname, op, grpc_ret["rtVxlanCfgResults"], expect_res))
            else:
                self.assert_("%s vxlan mroute faild, not expected" % (op),
                            grpc_ret["result"]["info"] == "success")

    def create_mroute(self, vrfname, vxlan_info_list, check=True):
        """
        创建vxlan mroute路由
        :param vrfname: vrf name
        :param vxlan_info_list: vxlan路由信息列表
            item: eg: {"prefix": "1.1.1.1", "plen": 32, "nexthop": "2.2.2.2", "vni": 100, "gateway": "0.0.0.0", "expect_res": "success"}
        :return
        """
        self._handle_vxlan_mroute(vrfname, vxlan_info_list, "create", check)

    def delete_mroute(self, vrfname, vxlan_info_list, check=True):
        """
        删除vxlan mroute路由
        :param vrfname: vrf name
        :param vxlan_info_list: vxlan路由信息列表
            item: eg: {"prefix": "1.1.1.1", "plen": 32, "nexthop": "2.2.2.2", "vni": 100, "gateway": "0.0.0.0", "expect_res": "success"}
        :return
        """
        self._handle_vxlan_mroute(vrfname, vxlan_info_list, "delete", check)

    # -------------------------------addVrfRouteGre/delVrfRouteGre grpc-----------------------#
    def check_gre_route_count(self, vrfname, expect_res):
        in_device_gre_route_cfgs = {}
        in_device_gre_route_prefixs = {}
        cfgtypes = ["routeGres"]
        in_device_cfgs = self.ntb_grpc_client.get_ntb_vrf_config(vrfname, cfgtypes)
        for rt_gre in in_device_cfgs["routeGres"]:
            _, pip, plen = self._parse_prefix_dict(rt_gre["prefix"])
            _, nip = self._parse_ipaddr_dict(rt_gre["nexthopIp"])
            vpcid = rt_gre["vpcId"]["id"]
            key = "%s/%d-%s-%d" % (pip, plen, nip, vpcid)
            prefixkey = "%s/%d" % (pip, plen)
            in_device_gre_route_cfgs[key] = rt_gre
            if prefixkey in in_device_gre_route_prefixs:
                in_device_gre_route_prefixs[prefixkey] = in_device_gre_route_prefixs[prefixkey] + 1
            else:
                in_device_gre_route_prefixs[prefixkey] = 1

        for prefixkey, value in expect_res.items():
            if prefixkey not in in_device_gre_route_prefixs:
                if value != 0:
                    self.assert_("gre route prefix %s rpath count not expected, expect %d but 0" %
                              (prefixkey, value), False)
                continue

            if value != in_device_gre_route_prefixs[prefixkey]:
                self.assert_( "gre route prefix %s rpath count not expected, expect %d but %d" %
                              (prefixkey, value, in_device_gre_route_prefixs[prefixkey]), False)

    # -------------------------------addVrfRouteGre/delVrfRouteGre grpc-----------------------#
    def _check_gre_route_res(self, vrfname, op, res, expect_res):
        in_device_gre_route_cfgs = {}
        in_device_gre_route_prefixs = {}
        cfgtypes = ["routeGres"]
        in_device_cfgs = self.ntb_grpc_client.get_ntb_vrf_config(vrfname, cfgtypes)
        for rt_gre in in_device_cfgs["routeGres"]:
            _, pip, plen = self._parse_prefix_dict(rt_gre["prefix"])
            _, nip = self._parse_ipaddr_dict(rt_gre["nexthopIp"])
            vpcid = rt_gre["vpcId"]["id"]
            if "vmIp" not in rt_gre:
                vmip = "0.0.0.0"
            else:
                _, vmip = self._parse_ipaddr_dict(rt_gre["vmIp"])
            key = "%s/%d-%s-%d-%s" % (pip, plen, nip, vpcid, vmip)
            prefixkey = "%s/%d" % (pip, plen)
            in_device_gre_route_cfgs[key] = rt_gre
            if prefixkey in in_device_gre_route_prefixs:
                in_device_gre_route_prefixs[prefixkey] = in_device_gre_route_prefixs[prefixkey] + 1
            else:
                in_device_gre_route_prefixs[prefixkey] = 1

        for item in res:
            if "prefix" in item["rtGre"]:
                _, pip, plen = self._parse_prefix_dict(item["rtGre"]["prefix"])
            else:
                pip = "0.0.0.0"
                plen = 0
                item["rtGre"]["prefix"] = self._encap_prefix_item(pip, plen, "ipv4")
            if "nexthopIp" in item["rtGre"]:
                _, nip = self._parse_ipaddr_dict(item["rtGre"]["nexthopIp"])
            else:
                nip = "0.0.0.0"
                item["rtGre"]["nexthopIp"] = self._encap_ip_item(nip, "ipv4")

            if "vmIp" not in item["rtGre"]:
                item["rtGre"]["vmIp"] = self._encap_ip_item("0.0.0.0", "ipv4")
                vmip = "0.0.0.0"
            else:
                _, vmip = self._parse_ipaddr_dict(item["rtGre"]["vmIp"])

            if "vpcId" in item["rtGre"]:
                vpcid = item["rtGre"]["vpcId"]["id"]
            else:
                vpcid = 0
                item['rtGre']['vpcId'] = {"id": vpcid}

            key = "%s/%d-%s-%d-%s" % (pip, plen, nip, vpcid, vmip)
            prefixkey = "%s/%d" % (pip, plen)
            value = item["rtGre"]
            e_res = expect_res[key]
            if e_res != item["result"]["info"]:
                self.log_info(
                    "%s gre route %s result not expected, expect %s but %s" % (op, key, e_res, item["result"]["info"]))
                return False
            if op == "create":
                if e_res == "success":
                    if key not in in_device_gre_route_cfgs:
                        self.log_info("%s gre route  %s success, but not set in device" % (op, key))
                        return False
                    # gre配置核查不显示weight
                    if "weight" in value:
                        value_copy = value.copy()  # 创建value的副本
                        value_copy['weight'] = 0   # 在副本上修改weight
                    else:
                        value_copy = value
                    if in_device_gre_route_cfgs[key] != value_copy:
                        self.log_info("%s gre route  %s success, but %s inconsitent with %s in device" %
                                      (op, key, str(value), str(in_device_gre_route_cfgs[key])))
                        return False
            else:
                if e_res == "success":
                    if nip == "0.0.0.0" and prefixkey in in_device_gre_route_prefixs:
                        self.log_info("%s gre route  %s success, but prefix %s still in device" % (op, key, prefixkey))
                        return False

                    if key in in_device_gre_route_cfgs:
                        self.log_info("%s gre route  %s success, but still in device" % (op, key))
                        return False
        return True

    def _handle_gre_route(self, vrfname, gre_infos, op, check=True, expect_grpc_ret="success"):
        """
        下发gre路由配置
        """
        if len(gre_infos) == 0:
            return
        dict_request = {
            "vrf": {
                "vrfName": vrfname
            },
            "rtGres": [
            ]
        }
        expect_res = {}
        for index in range(len(gre_infos)):
            gre_info = gre_infos[index]
            item = {}
            if "prefix" in gre_info:
                item["prefix"] = self._encap_prefix_item(gre_info["prefix"], gre_info["plen"], "ipv4")
            else:
                gre_info["prefix"] = "0.0.0.0"
                gre_info["plen"] = 0

            if "nexthop" in gre_info:
                item["nexthopIp"] = self._encap_ip_item(gre_info["nexthop"], "ipv4")
            else:
                gre_info["nexthop"] = "0.0.0.0"

            if "vmip" in gre_info:
                item["vmIp"] = self._encap_ip_item(gre_info["vmip"], "ipv4")
            else:
                gre_info["vmip"] = "0.0.0.0"
            
            if "vpcid" in gre_info:
                item["vpcId"] = {"id": gre_info["vpcid"]}
            else:
                gre_info["vpcid"] = 0

            if "weight" in gre_info:
                item["weight"] = gre_info["weight"]

            dict_request["rtGres"].append(item)
            expect_key = "%s/%d-%s-%d-%s" % (gre_info["prefix"], gre_info["plen"], gre_info["nexthop"], gre_info["vpcid"], gre_info["vmip"])
            if "expect_res" not in gre_info:
                gre_info["expect_res"] = "success"
            expect_res[expect_key] = gre_info["expect_res"]
            if (index + 1) % 20000 == 0:
                grpc_ret = None
                if op == "create":
                    grpc_ret = self.ntb_grpc_client.grpc_call("addVrfRouteGre", dict_request)
                else:
                    grpc_ret = self.ntb_grpc_client.grpc_call("delVrfRouteGre", dict_request)

                if check:
                    self.assert_("%s gre route faild, not expected" % (op),
                                self._check_gre_route_res(vrfname, op, grpc_ret["rtGreCfgResults"], expect_res))
                    if expect_grpc_ret != "success":
                        self.assert_("%s gre route %s, not expected" % (op, grpc_ret["result"]["info"]),
                                    grpc_ret["result"]["info"] == expect_grpc_ret)
                else:
                    self.assert_("%s gre route %s, not expected" % (op, grpc_ret["result"]["info"]),
                                grpc_ret["result"]["info"] == expect_grpc_ret)
                expect_res = {}
                dict_request["rtGres"].clear()
        if len(dict_request["rtGres"]) > 0:
            grpc_ret = None
            if op == "create":
                grpc_ret = self.ntb_grpc_client.grpc_call("addVrfRouteGre", dict_request)
            else:
                grpc_ret = self.ntb_grpc_client.grpc_call("delVrfRouteGre", dict_request)

            if check:
                self.assert_("%s gre route faild, not expected" % (op),
                            self._check_gre_route_res(vrfname, op, grpc_ret["rtGreCfgResults"], expect_res))
                if expect_grpc_ret != "success":
                    self.assert_("%s gre route %s, not expected" % (op, grpc_ret["result"]["info"]),
                                grpc_ret["result"]["info"] == expect_grpc_ret)
            else:
                self.assert_("%s gre route %s, not expected" % (op, grpc_ret["result"]["info"]),
                            grpc_ret["result"]["info"] == expect_grpc_ret)

    def create_gre_route(self, vrfname, gre_info_list, check=True):
        """
        创建gre mroute路由
        :param vrfname: vrf name
        :param gre_info_list: gre路由信息列表
            item: eg: {"prefix": "1.1.1.1", "plen": 32, "nexthop": "2.2.2.2", "vpcid": 100, "vmip": "0.0.0.0", "expect_res": "success"}
        :return
        """
        self._handle_gre_route(vrfname, gre_info_list, "create", check)

    def delete_gre_route(self, vrfname, gre_info_list, check=True):
        """
        删除gre mroute路由
        :param vrfname: vrf name
        :param gre_info_list: gre路由信息列表
            item: eg: {"prefix": "1.1.1.1", "plen": 32, "nexthop": "2.2.2.2", "vpcid": 100, "vmip": "0.0.0.0", "expect_res": "success"}
        :return
        """
        self._handle_gre_route(vrfname, gre_info_list, "delete", check)

    def create_gre_route_with_fail(self, vrfname, gre_info_list, check=True, expect_grpc_ret="failure"):
        """
        创建gre mroute路由
        :param vrfname: vrf name
        :param gre_info_list: gre路由信息列表
            item: eg: {"prefix": "1.1.1.1", "plen": 32, "nexthop": "2.2.2.2", "vpcid": 100, "vmip": "0.0.0.0", "expect_res": "success"}
        :param expect_grpc_ret: expected grpc return value
        :return
        """
        self._handle_gre_route(vrfname, gre_info_list, "create", check, expect_grpc_ret)

    def _check_gre_route_status(self, vrfname, gre_info_list, exist):
        in_device_gre_route_cfgs = {}
        cfgtypes = ["routeGres"]
        in_device_cfgs = self.ntb_grpc_client.get_ntb_vrf_config(vrfname, cfgtypes)
        for rt_gre in in_device_cfgs["routeGres"]:
            _, pip, plen = self._parse_prefix_dict(rt_gre["prefix"])
            _, nip = self._parse_ipaddr_dict(rt_gre["nexthopIp"])
            vpcid = rt_gre["vpcId"]["id"]
            key = "%s/%d-%s-%d" % (pip, plen, nip, vpcid)
            in_device_gre_route_cfgs[key] = rt_gre

        for gre_info in gre_info_list:
            key = "%s/%d-%s-%d" % (gre_info["prefix"], gre_info["plen"], gre_info["nexthop"], gre_info["vpcid"])
            if exist:
                if key not in in_device_gre_route_cfgs:
                    self.assert_("%s gre route not exist" % (key), False)
            else:
                if key in in_device_gre_route_cfgs:
                    self.assert_("%s gre route exist" % (key), False)

    def check_gre_route_exist(self, vrfname, gre_info_list):
        """
        检查路由信息是否存在
        :param vrfname: vrf name
        :param gre_info_list: gre路由信息列表
            item: eg: {"prefix": "1.1.1.1", "plen": 32, "nexthop": "2.2.2.2", "vpcid": 100, "vmip": "0.0.0.0", "expect_res": "success"}
        :return
        """
        self._check_gre_route_status(vrfname, gre_info_list, True)

    def check_gre_route_not_exist(self, vrfname, gre_info_list):
        """
        检查路由信息是否不存在
        :param vrfname: vrf name
        :param gre_info_list: gre路由信息列表
            item: eg: {"prefix": "1.1.1.1", "plen": 32, "nexthop": "2.2.2.2", "vpcid": 100, "vmip": "0.0.0.0", "expect_res": "success"}
        :return
        """
        self._check_gre_route_status(vrfname, gre_info_list, False)

    # -------------------------------updateVrfRoute grpc-----------------------#
    def _commpare_dicts_list(list1, list2, exclude_keys=None):
        if len(list1) != len(list2):
            return False
        if exclude_keys is None:
            exclude_keys = []
        for dict1 in list1:
            dict1_filtered = {k: v for k, v in dict1.items() if k not in exclude_keys}
            if dict1_filtered not in list2:
                return False
        return True

    def _check_update_route_res(self, vrfname, res, expect_res, dict_request):
        in_device_route_cfg = {}
        cfgtypes = ["routeVxlans", "routeGres", "mrouteVxlans", "bhRoutes"]

        request = {}
        for i in dict_request["routes"]:
            _, pip, plen = self._parse_prefix_dict(i["prefix"])
            table = i['tableId']
            key = '%s/%d-%d' % (pip, plen, table)
            if key not in request:
                request[key] = []
            if i['rtType'] == 2:
                continue
            if i['rtType'] == 0:
                for nhop in i['vxlanNexthops']:
                    if 'weight' in nhop and nhop['weight'] == 0:
                        nhop['weight'] = 2
            request[key].extend(i['vxlanNexthops'])
            request[key].extend(i['greNexthops'])

        in_device_cfgs = self.ntb_grpc_client.get_ntb_vrf_config(vrfname, cfgtypes)
        # print(in_device_cfgs)
        for i in in_device_cfgs['routeVxlans']:
            _, pip, plen = self._parse_prefix_dict(i['base']["prefix"])
            table = i['base']['tableId']
            key = '%s/%d-%d' % (pip, plen, table)
            if key not in in_device_route_cfg:
                in_device_route_cfg[key] = []
            item = i['base']
            del item["prefix"]
            del item["tableId"]
            in_device_route_cfg[key].append(item)

        for i in in_device_cfgs['routeGres']:
            _, pip, plen = self._parse_prefix_dict(i["prefix"])
            table = 0
            key = '%s/%d-%d' % (pip, plen, table)
            if key not in in_device_route_cfg:
                in_device_route_cfg[key] = []
            item = i
            del item['prefix']
            in_device_route_cfg[key].append(item)

        for i in in_device_cfgs['mrouteVxlans']:
            _, pip, plen = self._parse_prefix_dict(i['base']["prefix"])
            table = i['base']['tableId']
            key = '%s/%d-%d' % (pip, plen, table)
            if key not in in_device_route_cfg:
                in_device_route_cfg[key] = []
            item = i['base']
            del item["prefix"]
            del item["tableId"]
            in_device_route_cfg[key].append(item)

        for i in in_device_cfgs['bhRoutes']:
            _, pip, plen = self._parse_prefix_dict(i["prefix"])
            table = i['tableId']
            key = '%s/%d-%d' % (pip, plen, table)
            if key not in in_device_route_cfg:
                in_device_route_cfg[key] = []

        for item in res:
            _, pip, plen = self._parse_prefix_dict(item["prefix"])
            table_id = item["tableId"]
            key = "%s/%d-%d" % (pip, plen, table_id)
            e_res = expect_res[key]
            if e_res != item["result"]["info"]:
                self.log_info("update route %s result not expected, expect %s but %s" % (
                    key, e_res, item["result"]["info"]))
                return False
            if e_res == "success":
                if request[key] != in_device_route_cfg[key]:
                    self.log_info("update route %s result not expected, expect %s but inconsistent with device\n \
                                request: %s\n\
                                device: %s" % (key, e_res, request[key], in_device_route_cfg[key]))
                    return False
        return True

    def _handle_update_vrf_route(self, vrfname, route_infos):
        """
        更新vxlan路由配置
        """
        if len(route_infos) == 0:
            return
        dict_request = {
            "vrf": {
                "vrfName": vrfname
            },
            "routes": [
            ]
        }
        expect_res = {}
        for index in range(len(route_infos)):
            route = route_infos[index]
            item = {}
            item["prefix"] = self._encap_prefix_item(route["prefix"], route["plen"], "ipv4")
            if "rt_table" not in  route:
                item["tableId"] = 0
            else:
                item["tableId"] = route["rt_table"]
            if "rt_type" not in route:
                item["rtType"] = 0
            elif route['rt_type'] == 'normal':
                item["rtType"] = 0
            elif route['rt_type'] == 'mroute':
                item["rtType"] = 1
            elif route['rt_type'] == 'blackhole':
                item["rtType"] = 2
            else:
                item["rtType"] = 0

            item["vxlanNexthops"] = []
            item["greNexthops"] = []
            for nexthop in route["nexthops"]:
                if 'vni' in nexthop:
                    nexthop_item = {}

                    nexthop_item["nexthopIp"] = self._encap_ip_item(nexthop["nexthop"], "ipv4")
                    nexthop_item["vni"] = nexthop["vni"]
                    nexthop_item["dscp"] = 0
                    nexthop_item["weight"] = nexthop["weight"] if "weight" in nexthop else 0
                    if "gateway" not in nexthop:
                        if item["prefix"]["family"] == 2:
                            nexthop_item["gateway"] = self._encap_ip_item("::", "ipv4")
                        else:
                            nexthop_item["gateway"] = self._encap_ip_item("0.0.0.0", "ipv4")
                    else:
                        nexthop_item["gateway"] = self._encap_ip_item(nexthop["gateway"], "ipv4")
                    
                    item["vxlanNexthops"].append(nexthop_item)
                else:
                    nexthop_item = {}

                    nexthop_item["nexthopIp"] = self._encap_ip_item(nexthop["nexthop"], "ipv4")
                    nexthop_item["vpcId"] =  {"id": nexthop["vpcid"]}
                    nexthop_item["weight"] = nexthop["weight"] if "weight" in nexthop else 0
                    if 'vmip' not in nexthop:
                        nexthop['vmip'] = '0.0.0.0'
                    nexthop_item["vmIp"] = self._encap_ip_item(nexthop["vmip"], "ipv4")                    
                    item["greNexthops"].append(nexthop_item)

            dict_request["routes"].append(item)
            expect_key = "%s/%d-%d" % (
                route["prefix"], route["plen"], item["tableId"])
            if "expect_res" not in route:
                route["expect_res"] = "success"
            expect_res[expect_key] = route["expect_res"]
            if (index + 1) % 1000 == 0:
                grpc_ret = self.ntb_grpc_client.grpc_call("updateVrfRoute", dict_request)
                self.assert_("update route faild, not expected",
                             self._check_update_route_res(vrfname, grpc_ret["rtResults"], expect_res, dict_request))
                expect_res = {}
                dict_request["routes"].clear()
        if len(dict_request["routes"]) > 0:
            grpc_ret = self.ntb_grpc_client.grpc_call("updateVrfRoute", dict_request)
            self.assert_("update route faild, not expected",
                         self._check_update_route_res(vrfname, grpc_ret["rtResults"], expect_res, dict_request))

    def update_vrf_route(self, vrfname, route_list):
        """
        创建vxlan路由
        :param vrfname: vrf name
        :param vxlan_info_list: vxlan路由信息列表
            item: eg: {"prefix": "1.1.1.1", "plen": 32, "rt_table":0, "nexthops":[], "expect_res": "success"}
                nexthop_item: {"nexthop": "2.2.2.2", "vni": 100, "gateway": "0.0.0.0"}
        :return
        """
        self._handle_update_vrf_route(vrfname, route_list)

    # -------------------------------reportchannel regist/get grpc-----------------------#
    def trans_vrf_info_pb_to_human(self, vrf_info_pb):
        """
        将vrf pb信息转换成可读性更好的结构
        :param vrfname: vrf name
        :return vrf_info_result map
        """
        vrf_info_result = {}

        vrf_name = vrf_info_pb["vrfInfo"]["vrfName"]

        _, vrf_ip, _ = self._parse_prefix_dict(vrf_info_pb["internalVrfIp"]["ip"])
        vrf_info_result["vrf_ip"] = vrf_ip

        _, vrf_ipv6, _ = self._parse_prefix_dict(vrf_info_pb["internalVrfIp6"]["ip"])
        vrf_info_result["vrf_ipv6"] = vrf_ipv6

        _, vrf_vpcipv6, _ = self._parse_prefix_dict(vrf_info_pb["vpcIp6"]["ip"])
        vrf_info_result["vrf_vpcipv6"] = vrf_vpcipv6

        route_mac = vrf_info_pb["routeMacs"][0]["mac"]
        vrf_info_result["route_mac"] = route_mac

        vxlan_tuns = {}
        for vxlan_tun_pb in vrf_info_pb["tunnelVxlans"]:
            vni = vxlan_tun_pb["vxlanVni"]
            vxlan_tuns[vni] = {"vni": vni}
        vrf_info_result["vxlan_tunnels"] = vxlan_tuns

        tunnel_bundles = {}
        for tun_bundle_pb in vrf_info_pb["tunnelBundleVxlans"]:
            i_vni = tun_bundle_pb["vxlanVni_i"]
            o_vni = tun_bundle_pb["vxlanVni_o"]
            bundle_key = "%d-%d" % (i_vni, o_vni)
            tunnel_bundles[bundle_key] = {"ivni": i_vni, "ovni": o_vni}
        vrf_info_result["tunnel_bundles"] = tunnel_bundles

        gre_tunnels = {}
        for gre_tun_pb in vrf_info_pb["tunnelGres"]:
            vpc_id = gre_tun_pb["greVpcId"]
            gre_tunnels[vpc_id] = {"vpcid": vpc_id}
        vrf_info_result["gre_tunnels"] = gre_tunnels

        agent_arps = {}
        for agent_arp_pb in vrf_info_pb["neighProxys"]:
            _, tip = self._parse_ipaddr_dict(agent_arp_pb["ip"])
            agent_arps[tip] = {"ip": tip}
        vrf_info_result["agent_arps"] = agent_arps

        vxlan_routes = {}
        for rt_vxlan_pb in vrf_info_pb["routeVxlans"]:
            _, pip, plen = self._parse_prefix_dict(rt_vxlan_pb["base"]["prefix"])
            _, nip = self._parse_ipaddr_dict(rt_vxlan_pb["base"]["nexthopIp"])
            _, gw_ip = self._parse_ipaddr_dict(rt_vxlan_pb["base"]["gateway"])
            vni = rt_vxlan_pb["base"]["vni"]
            key = "%s/%d" % (pip, plen)
            vxlan_routes[key] = {"prefix": pip, "plen": plen, "nexthop": nip, "vni": vni, "gateway": gw_ip}
        vrf_info_result["vxlan_routes"] = vxlan_routes

        vxlan_mroutes = {}
        for rt_vxlan_pb in vrf_info_pb["mrouteVxlans"]:
            _, pip, plen = self._parse_prefix_dict(rt_vxlan_pb["base"]["prefix"])
            _, nip = self._parse_ipaddr_dict(rt_vxlan_pb["base"]["nexthopIp"])
            _, gw_ip = self._parse_ipaddr_dict(rt_vxlan_pb["base"]["gateway"])
            vni = rt_vxlan_pb["base"]["vni"]
            key = "%s/%d" % (pip, plen)
            vxlan_mroutes[key] = {"prefix": pip, "plen": plen, "nexthop": nip, "vni": vni, "gateway": gw_ip}
        vrf_info_result["vxlan_mroutes"] = vxlan_mroutes

        gre_routes = {}
        for rt_gre_pb in vrf_info_pb["routeGres"]:
            _, pip, plen = self._parse_prefix_dict(rt_gre_pb["prefix"])
            _, nip = self._parse_ipaddr_dict(rt_gre_pb["nexthopIp"])
            _, vm_ip = self._parse_ipaddr_dict(rt_gre_pb["vmIp"])
            vpcid = rt_gre_pb["vpcId"]["id"]
            key = "%s/%d" % (pip, plen)
            gre_routes[key] = {"prefix": pip, "plen": plen, "nexthop": nip, "vpcid": vpcid, "vmip": vm_ip}
        vrf_info_result["gre_routes"] = gre_routes

        blackhole_routes = {}
        for rt_blackhole_pb in vrf_info_pb["bhRoutes"]:
            _, pip, plen = self._parse_prefix_dict(rt_blackhole_pb["prefix"])
            tableid = rt_blackhole_pb["tableId"]
            key = "%s/%d" % (pip, plen)
            blackhole_routes[key] = {"prefix": pip, "plen": plen}
            if tableid != 0:
                blackhole_routes[key]["table_id"] = tableid
        vrf_info_result["blackhole_routes"] = blackhole_routes

        rt_tables = {}
        for rt_table_pb in vrf_info_pb["ipTables"]:
            tableid = rt_table_pb["tableId"]
            if tableid == 0:
                continue
            rt_tables[tableid] = {"table_id": int(tableid)}
        vrf_info_result["rt_tables"] = rt_tables

        sflow_rules = {}
        if "sflow" in vrf_info_pb:
            stype = vrf_info_pb["sflow"]["serviceType"]
            ssid = vrf_info_pb["sflow"]["serviceId"]
            action = vrf_info_pb["sflow"]["action"]
            sflow_rules[vrf_name] =  {"vrf":vrf_name, "serviceType":stype, "serviceId":ssid, "action":action}
        vrf_info_result["sflow_rules"] = sflow_rules

        vni_mtus = {}
        for vni_mtu_pb in vrf_info_pb["vniMtuInfos"]:
            vni = vni_mtu_pb["vni"]
            mtu = vni_mtu_pb["mtu"]
            vni_mtus[vni] = {"vni": int(vni), "mtu": int(mtu)}
        vrf_info_result["vni_mtus"] = vni_mtus

        xconnects = {}
        for xconnect_pb in vrf_info_pb["xConnects"]:
            in_vni = xconnect_pb["invxlanVni"]
            out_vni = xconnect_pb["outvxlanVni"]
            _, rip = self._parse_ipaddr_dict(xconnect_pb["remoteIp"])
            dscp = xconnect_pb["dscp"] 
            xconnects[in_vni] = {"in_vni": in_vni, "nexthop": rip, "out_vni": out_vni, "dscp": dscp}
        vrf_info_result["xconnects"] = xconnects

        xconnects_qos = {}
        for xconnect_qos_pb in vrf_info_pb["tunQosMeters"]:
            vni = xconnect_qos_pb["vni"]
            qos = xconnect_qos_pb["qos"]
            xconnects_qos[vni] = {"vni": vni, "qos": qos}
        vrf_info_result["xconnects_qos"] = xconnects_qos

        sport_hash_rules = {}
        for sport_hash_rule_pb in vrf_info_pb["vxlanSportHashRules"]:
            mac_type = sport_hash_rule_pb["mac_type"]
            ip_proto = sport_hash_rule_pb["ip_proto"]
            dst_port = sport_hash_rule_pb["dst_port"]
            hash_mode_str = ""
            hash_mode = sport_hash_rule_pb["hash_mode"]
            if hash_mode == 0:
                hash_mode_str  = "normal"
            elif hash_mode == 1:
                hash_mode_str  = "ten_tuple"
            else:
                hash_mode_str  = "perpacket"
            key = "%d_%d_%d" % (mac_type, ip_proto, dst_port)
            sport_hash_rules[key] = {"mac_type":mac_type, "ip_proto": ip_proto, "dst_port": dst_port, "hash_mode": hash_mode_str}
        vrf_info_result["sport_hash_rules"] = sport_hash_rules

        accel_chans = {}
        for entry in vrf_info_pb["accelChannels"]:
            name = entry["name"]
            region = entry["region"]
            accel_chans[name] = {"name": name, "region": region}
        vrf_info_result["accel_chans"] = accel_chans 

        accel_chan_qos = {}
        for entry in vrf_info_pb["qosToAccelChannels"]:
            name = entry["accelChan"]
            qos = entry["qos"]
            accel_chan_qos[name] = {"name": name, "qos": qos}
        vrf_info_result["accel_chan_qos"] = accel_chan_qos

        accel_chan_tuns = {}
        for entry in vrf_info_pb["tunToAccelChannels"]:
            name = entry["accelChan"]
            ivni = int(entry["invxlanVni"])
            ovni = int(entry["outvxlanVni"])
            tun_type = "peer"
            ttype = entry["type"]
            if ttype == 0:
                tun_type = "local"
            accel_chan_tuns["%s_%d_%d" % (name, ivni, ovni)] = {"name": name, "in_vni": ivni, "out_vni": ovni, "tun_type": tun_type}
        vrf_info_result["accel_chan_tuns"] = accel_chan_tuns

        return vrf_info_result

    # -------------------------------reportchannel regist/get grpc-----------------------#
    def regist_report_channel(self, report_channel):
        """
        注册上报通道
        :param report_channel: 上报通道信息
           {order:0-master/1-slave, ipaddr:"1.1.1.1", port:1234} 
        :return
        """
        dict_request = {
            "reportChannes": [
                {
                    "ip": self._encap_ip_item(report_channel["ipaddr"], "ipv4"),
                    "port": int(report_channel["port"]),
                    "order": report_channel["order"],
                    "interval": 1000
                }
            ]
        }
        grpc_ret = self.ntb_grpc_client.grpc_call("registerReportChannel", dict_request)
        self.assert_("regist report channel faild", grpc_ret["info"] == "success")

    def get_report_channel(self):
        """
        获取当前设备注册的上报通道信息
        :param 
        :return report_channel_list
            {order:"master", ipaddr:"1.1.1.1", port:1234, status:True}
        """
        report_channel_list = []
        grpc_ret = self.ntb_grpc_client.grpc_call("getRegistedReportServers", {})
        self.assert_("get report channel faild", grpc_ret["result"]["info"] == "success")
        for report_channel_pb in grpc_ret["reportServers"]:
            report_channel_item = {}
            server_addr = report_channel_pb["serverAddr"].split(":")
            report_channel_item["order"] = report_channel_pb["order"]
            report_channel_item["status"] = report_channel_pb["status"]
            report_channel_item["ipaddr"] = server_addr[0]
            report_channel_item["port"] = server_addr[1]
            report_channel_list.append(report_channel_item)
        return report_channel_list


    # -------------------------------accel channel grpc-----------------------#
    def _check_accel_channel_res(self, vrfname, op, res, expect_res):
        in_device_cfgs = {}
        cfgtypes = ["accelChannels"]
        in_device_all_cfgs = self.ntb_grpc_client.get_ntb_vrf_config(vrfname, cfgtypes)
        for entry in in_device_all_cfgs["accelChannels"]:
            name = entry["name"]
            in_device_cfgs[name] = entry

        for item in res:
            name = item["channel"]["name"]
            value = item["channel"]
            key = name
            e_res = expect_res
            if e_res != item["result"]["info"]:
                self.log_info("%s accelchannel %s result not expected, expect %s but %s" % (
                    op, key, e_res, item["result"]["info"]))
                return False
            if op == "create":
                if e_res == "success":
                    if name not in in_device_cfgs:
                        self.log_info("%s accelchannel  %s success, but not set in device" % (op, key))
                        return False
                    if in_device_cfgs[key] != value:
                        self.log_info("%s accelchannel  %s success, but %s inconsitent with %s in device" %
                                      (op, key, str(value), str(in_device_cfgs[key])))
                        return False
            else:
                if e_res == "success":
                    if key in in_device_cfgs:
                        self.log_info("%s accelchannel %s success, but still in device" % (op, key))
                        return False
        return True

    def _handle_accel_channel(self, vrfname, accel_name, accel_region, op, expect_res):
        dict_request = {
            "vrf": {
                "vrfName": vrfname
            },
            "channels": [
            ]
        }

        item = {}
        item["name"] = accel_name
        item["region"] = accel_region
        dict_request["channels"].append(item)

        grpc_ret = None
        if op == "create":
            grpc_ret = self.ntb_grpc_client.grpc_call("addAccelerlateChannel", dict_request)
        else:
            grpc_ret = self.ntb_grpc_client.grpc_call("delAccelerlateChannel", dict_request)

        self.assert_("%s accel channel faild, not expected" % (op),
                    self._check_accel_channel_res(vrfname, op, grpc_ret["accelChannelResults"], expect_res))

    def _check_tun_to_accel_chan_res(self, vrfname, op, res, expect_res):
        in_device_cfgs = {}
        cfgtypes = ["tunToAccelChannels"]
        in_device_all_cfgs = self.ntb_grpc_client.get_ntb_vrf_config(vrfname, cfgtypes)
        for entry in in_device_all_cfgs["tunToAccelChannels"]:
            name = entry["accelChan"]
            in_vni = entry["invxlanVni"]
            out_vni = entry["outvxlanVni"]
            key = "%s-%s-%s" % (name, in_vni, out_vni)
            in_device_cfgs[key] = entry

        for item in res:
            name = item["tunToAccelChan"]["accelChan"]
            in_vni = item["tunToAccelChan"]["invxlanVni"]
            out_vni = item["tunToAccelChan"]["outvxlanVni"]
            key = "%s-%s-%s" % (name, in_vni, out_vni)
            value = item["tunToAccelChan"]
            e_res = expect_res[key]
            if e_res != item["result"]["info"]:
                self.log_info("%s tun to accelchannel %s result not expected, expect %s but %s" % (
                    op, key, e_res, item["result"]["info"]))
                return False
            if op == "bind":
                if e_res == "success":
                    if key not in in_device_cfgs:
                        self.log_info("%s tun to accelchannel  %s success, but not set in device" % (op, key))
                        return False
                    if in_device_cfgs[key] != value:
                        self.log_info("%s tun to accelchannel  %s success, but %s inconsitent with %s in device" %
                                      (op, key, str(value), str(in_device_cfgs[key])))
                        return False
            else:
                if e_res == "success":
                    if key in in_device_cfgs:
                        self.log_info("%s tun to accelchannel %s success, but still in device" % (op, key))
                        return False
        return True

    def _handle_accel_channel_tun_bind(self, vrfname, accel_name, tun_to_accel_list, op):
        if len(tun_to_accel_list) == 0:
            return
        dict_request = {
            "vrf": {
                "vrfName": vrfname
            },
            "tunToAccelChans": [
            ]
        }
        expect_res = {}
        for index in range(len(tun_to_accel_list)):
            entry = tun_to_accel_list[index]
            item = {}
            item["accelChan"] = accel_name
            item["invxlanVni"] = int(entry["in_vni"])
            item["outvxlanVni"] = int(entry["out_vni"])
            if entry['tun_type'] == "local":
                item["type"] = 0
            else:
                item["type"] = 1
            dict_request["tunToAccelChans"].append(item)
            expect_key = "%s-%s-%s" % (accel_name, entry["in_vni"], entry["out_vni"])
            if "expect_res" not in entry:
                entry["expect_res"] = "success"
            expect_res[expect_key] = entry["expect_res"]
            if (index + 1) % 20000 == 0:
                grpc_ret = None
                if op == "bind":
                    grpc_ret = self.ntb_grpc_client.grpc_call("bindTunnelToAccelChannel", dict_request)
                else:
                    grpc_ret = self.ntb_grpc_client.grpc_call("unbindTunnelToAccelChannel", dict_request)

                self.assert_("%s tun to accel channel faild, not expected" % (op),
                            self._check_tun_to_accel_chan_res(vrfname, op, grpc_ret["tunToAccelChanResults"], expect_res))
                expect_res = {}
                dict_request["tunToAccelChans"].clear()
        if len(dict_request["tunToAccelChans"]) > 0:
            grpc_ret = None
            if op == "bind":
                grpc_ret = self.ntb_grpc_client.grpc_call("bindTunnelToAccelChannel", dict_request)
            else:
                grpc_ret = self.ntb_grpc_client.grpc_call("unbindTunnelToAccelChannel", dict_request)

            self.assert_("%s tun to accel channel faild, not expected" % (op),
                        self._check_tun_to_accel_chan_res(vrfname, op, grpc_ret["tunToAccelChanResults"], expect_res))

    def _check_qos_to_accel_channel_res(self, vrfname, op, res, expect_res):
        in_device_cfgs = {}
        cfgtypes = ["qosToAccelChannels"]
        in_device_all_cfgs = self.ntb_grpc_client.get_ntb_vrf_config(vrfname, cfgtypes)
        for entry in in_device_all_cfgs["qosToAccelChannels"]:
            name = entry["accelChan"]
            in_device_cfgs[name] = entry

        for item in res:
            name = item["qosToAccelChan"]["accelChan"]
            value = item["qosToAccelChan"]
            key = name
            e_res = expect_res
            if e_res != item["result"]["info"]:
                self.log_info("%s qos to accelchannel %s result not expected, expect %s but %s" % (
                    op, key, e_res, item["result"]["info"]))
                return False
            if op == "bind":
                if e_res == "success":
                    if name not in in_device_cfgs:
                        self.log_info("%s qos to accelchannel  %s success, but not set in device" % (op, key))
                        return False
                    if in_device_cfgs[key] != value:
                        self.log_info("%s qos to accelchannel  %s success, but %s inconsitent with %s in device" %
                                      (op, key, str(value), str(in_device_cfgs[key])))
                        return False
            else:
                if e_res == "success":
                    if key in in_device_cfgs:
                        self.log_info("%s qos to accelchannel %s success, but still in device" % (op, key))
                        return False
        return True

    def _handle_accel_channel_qos_bind(self, vrfname, accel_name, qos_name, op, expect_res):
        dict_request = {
            "vrf": {
                "vrfName": vrfname
            },
            "qosToAccelChans": [
            ]
        }

        item = {}
        item["accelChan"] = accel_name
        item["qos"] = qos_name
        dict_request["qosToAccelChans"].append(item)

        grpc_ret = None
        if op == "bind":
            grpc_ret = self.ntb_grpc_client.grpc_call("bindQosToAccelChannel", dict_request)
        else:
            grpc_ret = self.ntb_grpc_client.grpc_call("unbindQosToAccelChannel", dict_request)

        self.assert_("%s qos to accel channel faild, not expected" % (op),
                    self._check_qos_to_accel_channel_res(vrfname, op, grpc_ret["qosToAccelChanResults"], expect_res))

    def create_accel_channel(self, vrfname, accel_name, accel_region, expect_res="success"):
        """
        创建加速通道
        :param vrfname: vrf name
        :return
        """
        self._handle_accel_channel(vrfname, accel_name, accel_region, "create", expect_res)

    def delete_accel_channel(self, vrfname, accel_name, expect_res="success"):
        """
        删除加速通道
        :param vrfname: vrf name
        :return
        """
        self._handle_accel_channel(vrfname, accel_name, "", "delete", expect_res)

    def bind_tunnel_to_accel_channel(self, vrfname, accel_name, tun_to_accel_list):
        """
        绑定隧道到加速通道
        :param vrfname: vrf name
        :param tun_to_accel_list: 
            item eg: {"in_vni": 1001, "out_vni": 1001, "tun_type": "local/peer"}
        :return
        """
        self._handle_accel_channel_tun_bind(vrfname, accel_name, tun_to_accel_list, "bind")

    def unbind_tunnel_to_accel_channel(self, vrfname, accel_name, tun_to_accel_list):
        """
        从加速通道中解绑隧道 
        :param vrfname: vrf name
        :param tun_to_accel_list: 
            item eg: {"in_vni": 1001, "out_vni": 1001, "tun_type": "local/peer"}
        :return
        """
        self._handle_accel_channel_tun_bind(vrfname, accel_name, tun_to_accel_list, "unbind")

    def bind_qos_to_accel_channel(self, vrfname, accel_name, qos_name, expect_res="success"):
        """
        绑定qos到加速通道
        :param vrfname: vrf name
        :return
        """
        self._handle_accel_channel_qos_bind(vrfname, accel_name, qos_name, "bind", expect_res)

    def unbind_qos_to_accel_channel(self, vrfname, accel_name, expect_res="success"):
        """
        解绑定qos到加速通道
        :param vrfname: vrf name
        :return
        """
        self._handle_accel_channel_qos_bind(vrfname, accel_name, "", "unbind", expect_res)

    # --------------------------------------------------------------------------#
    def get_vrf_ip_frag_stats(self):
        """
        获取基于vrf的分片报文统计
        :param 
        :return vrf_ip_frag_stats
            [{"vrfname":"vrf1", packets:1}]
        """
        vrf_ip_frag_stats = []
        grpc_ret = self.ntb_grpc_client.grpc_call("getVrfIpFragStats", {})
        self.assert_("get vrf ip frag stats faild", grpc_ret["result"]["info"] == "success")
        for vrf_stat in grpc_ret["stats"]:
            item = {}
            item["vrfname"] = vrf_stat["vrf"]
            item["packets"] = vrf_stat["packets"]
            vrf_ip_frag_stats.append(item)
        return vrf_ip_frag_stats

    def clear_vrf_ip_frag_stats(self):
        """
        清空基于vrf的分片报文统计
        :param 
        :return
        """
        grpc_ret = self.ntb_grpc_client.grpc_call("clrVrfIpFragStats", {})
        self.assert_("clear vrf ip frag stats faild", grpc_ret["info"] == "success")

    # -------------------------------lookStatisVrfTunnelVxlan/clearStatisVrfTunnelVxlan grpc-----------------------#
    def get_tunnel_vxlan_stats_by_vrf(self, vrfname):
        """
        获取基于vrf的vxlan隧道统计
        :param vrfname: vrf名称
        :return tunnel_vxlan_stats
            {5000: {"vrfname":"vrf1", "rx_packets":1, "rx_bytes":1, "tx_packets":1, "tx_bytes": 1}}
        """
        tunnel_vxlan_stats = {}
        dict_request = {
            "vrf": {
                "vrfName": vrfname
            },
            "tunnelVxlans": {}
        }
        grpc_ret = self.ntb_grpc_client.grpc_call("lookStatisVrfTunnelVxlan", dict_request)
        self.assert_("get vrf tunnelvxlan stats faild", grpc_ret["result"]["info"] == "success")
        for tunnel_stat in grpc_ret["tunnelCounterInfos"]:
            item = {}
            item["vrfname"] = vrfname
            item["vni"] = tunnel_stat["tunnelId"]
            item["rx_packets"] = tunnel_stat["rxOKPackets"]
            item["rx_bytes"] = tunnel_stat["rxOKbytes"]
            item["tx_packets"] = tunnel_stat["txOKPackets"]
            item["tx_bytes"] = tunnel_stat["txOKbytes"]
            tunnel_vxlan_stats[item["vni"]] = item
        return tunnel_vxlan_stats

    def clear_tunnel_vxlan_stats(self):
        """
        清空vxlan隧道统计
        :return
        """
        grpc_ret = self.ntb_grpc_client.grpc_call("clearStatisVrfTunnelVxlanAll", {})
        self.assert_("clear tunnelvxlan stats faild", grpc_ret["result"]["info"] == "success")

    # -------------------------------lookStatisVrfTunnelGre/clearStatisVrfTunnelGre grpc-----------------------#
    def get_tunnel_gre_stats_by_vrf(self, vrfname):
        """
        获取基于vrf的gre隧道统计
        :param vrfname: vrf名称
        :return tunnel_gre_stats
            {5000: {"vrfname":"vrf1", "rx_packets":1, "rx_bytes":1, "tx_packets":1, "tx_bytes": 1}}
        """
        tunnel_gre_stats = {}
        dict_request = {
            "vrf": {
                "vrfName": vrfname
            },
            "tunnelGres": {}
        }
        grpc_ret = self.ntb_grpc_client.grpc_call("lookStatisVrfTunnelGre", dict_request)
        self.assert_("get vrf tunnelgre stats faild", grpc_ret["result"]["info"] == "success")
        for tunnel_stat in grpc_ret["tunnelCounterInfos"]:
            item = {}
            item["vrfname"] = vrfname
            item["vpcid"] = tunnel_stat["tunnelId"]
            item["rx_packets"] = tunnel_stat["rxOKPackets"]
            item["rx_bytes"] = tunnel_stat["rxOKbytes"]
            item["tx_packets"] = tunnel_stat["txOKPackets"]
            item["tx_bytes"] = tunnel_stat["txOKbytes"]
            tunnel_gre_stats[item["vpcid"]] = item
        return tunnel_gre_stats

    def clear_tunnel_gre_stats(self):
        """
        清空gre隧道统计
        :return
        """
        grpc_ret = self.ntb_grpc_client.grpc_call("clearStatisVrfTunnelGreAll", {})
        self.assert_("clear tunnelgre stats faild", grpc_ret["result"]["info"] == "success")

    # -------------------------------getVrfDropStats/clrVrfDropStats grpc-----------------------#
    def get_vrf_drop_pkt_stats(self):
        """
        获取基于vrf的丢包统计
        params:
        return: vrf_drop_stat_map = {"vrf1": 100}
        """
        vrf_drop_stat_map = {}
        grpc_ret = self.ntb_grpc_client.grpc_call("getVrfDropStats", {})
        self.assert_("get vrf drop pkt stats faild", grpc_ret["result"]["info"] == "success")
        for vrf_drop_stat in grpc_ret["vrfdropstats"]:
            vrfname = vrf_drop_stat["vrf"]
            drop_pkts = vrf_drop_stat["drop_packets"]
            vrf_drop_stat_map[vrfname] = drop_pkts
        return vrf_drop_stat_map

    def clear_vrf_drop_pkt_stats(self):
        """
        清空基于vrf的丢包统计
        params:
        return: None
        """
        grpc_ret = self.ntb_grpc_client.grpc_call("clrVrfDropStats", {})
        self.assert_("clear vrf drop pkt stats faild", grpc_ret["info"] == "success")

    # -------------------------------getTfPktStats/clrTfPktStats grpc-----------------------#
    def _handle_tf_pkt_stats(self, op):
        """
        获取或清空丢包统计
        """
        drop_stats_map = {}
        grpc_ret = None
        if op == "get":
            grpc_ret = self.ntb_grpc_client.grpc_call("getTfPktStats", {})
            self.assert_("%s tf pkt stats faild" % (op), grpc_ret["result"]["info"] == "success")
            for stats_item in grpc_ret["tfPktStats"]:
                drop_stats_map[stats_item["statid"]] = stats_item["counter"]
            return drop_stats_map
        else:
            grpc_ret = self.ntb_grpc_client.grpc_call("clrTfPktStats", {})
            self.assert_("%s tf pkt stats faild" % (op), grpc_ret["info"] == "success")
            return None

    def get_tf_pkt_stats(self):
        """
        获取丢包统计
        params:
        return: drop_stats_map 
            'DROP_UNKNOWN': 0
            'DIP_NO_TERMINATE': 0
            'ETHERTYPE_NO_SUPPORT': 23
            ....
        """
        return self._handle_tf_pkt_stats("get")

    def clear_tf_pkt_stats(self):
        """
        清空丢包统计
        params:
        return: None
        """
        return self._handle_tf_pkt_stats("clr")

    def _handle_swf_pkt_stats(self, op):
        """
        获取或清空SWF丢包统计
        """
        drop_stats_map = {}
        grpc_ret = None
        if op == "get":
            grpc_ret = self.ntb_grpc_client.grpc_call("getSwfEvtStats", {})
            self.assert_("%s swf pkt stats faild" % (op), grpc_ret["result"]["info"] == "success")
            for stats_item in grpc_ret["swfEvtStats"]:
                drop_stats_map[stats_item["evtid"]] = stats_item["counter"]
            return drop_stats_map
        else:
            grpc_ret = self.ntb_grpc_client.grpc_call("clrSwfEvtStats", {})
            self.assert_("%s swf pkt stats faild" % (op), grpc_ret["info"] == "success")
            return None

    def get_swf_pkt_stats(self):
        """
        获取丢包统计
        params:
        return: drop_stats_map 
            'NETIO_MBUF_ALLOC_FAILED': 0
            'NETIO_MBUF_ALLOC_FAILED': 0
            'PACKET_MAX': 23
            ....
        """
        return self._handle_swf_pkt_stats("get")

    def clear_swf_pkt_stats(self):
        """
        清空丢包统计
        params:
        return: None
        """
        return self._handle_swf_pkt_stats("clr")

    # -------------------------------online/offline grpc-----------------------#
    def _handle_online_offline(self, online_status):
        dict_request = {
            "forwardStatus": online_status
        }
        grpc_ret = None
        grpc_ret = self.ntb_grpc_client.grpc_call("setForwardStatus", dict_request)
        self.assert_("set forward to %s faild, not expected" % (online_status), grpc_ret["info"] == "success")

    def online(self):
        """
        online设备
        :param ip: gre sip
        :return
        """
        self._handle_online_offline(True)

    def offline(self):
        """
        offline设备
        :param sip: gre sip
        :return
        """
        self._handle_online_offline(False)

    def recover_cross_test_cfg(self, fwd_ip=''):
        self.ntb_ssh_client.exec_cmd("config ntb device offline")
        self.ntb_ssh_client.exec_cmd("config ntb device cntlip unset")
        self.ntb_ssh_client.exec_cmd("config ntb device cntlip set --ip %s" % settings.NTB_CNTL_VIP)
        self.ntb_ssh_client.exec_cmd("config ntb device fwdvip unset")
        if fwd_ip == "":
            self.ntb_ssh_client.exec_cmd("config ntb device fwdvip set --ip %s" % settings.NTB_FWD_VIP)
        else:
            self.ntb_ssh_client.exec_cmd("config ntb device fwdvip set --ip %s" % fwd_ip)

    # -------------------------------addGreSip/delGreSip grpc-----------------------#
    def _handle_fwd_vip(self, vip, op):
        dict_request = {
            "ip": self._encap_ip_item(vip, "ipv4"),
        }
        grpc_ret = None
        if op == "set":
            grpc_ret = self.ntb_grpc_client.grpc_call("setForwardVip", dict_request)
            self.assert_("set fwd vip faild, not expected", grpc_ret["info"] == "success")
        elif op == "unset":
            grpc_ret = self.ntb_grpc_client.grpc_call("unsetForwardVip", dict_request)
            self.assert_("unset fwd vip faild, not expected", grpc_ret["info"] == "success")
        else:
            grpc_ret = self.ntb_grpc_client.grpc_call("getForwardVip", {})
            self.assert_("get fwd vip faild, not expected", grpc_ret["result"]["info"] == "success")
        if op == "get":
            _, ip = self._parse_ipaddr_dict(grpc_ret["ip"])
            return ip

    def set_fwd_vip(self, vip):
        """
        设置fwd vip
        :return
        """
        self.offline()
        self._handle_fwd_vip(vip, "set")

    def unset_fwd_vip(self, vip):
        """
        删除fwd vip
        :return
        """
        self.offline()
        self._handle_fwd_vip(vip, "unset")

    def get_fwd_vip(self):
        """
        获取fwd vip
        :return
        """
        return self._handle_fwd_vip("0.0.0.0", "get")

    # -------------------------------addGreSip/delGreSip grpc-----------------------#
    def _handle_gre_sip(self, sip, op):
        dict_request = {
            "ip": self._encap_ip_item(sip, "ipv4"),
        }
        grpc_ret = None
        if op == "add":
            grpc_ret = self.ntb_grpc_client.grpc_call("addGreSip", dict_request)
        else:
            grpc_ret = self.ntb_grpc_client.grpc_call("delGreSip", dict_request)
        self.assert_("%s gre sip faild, not expected" % (op), op, grpc_ret["info"] == "success")

    def add_gre_sip(self, sip):
        """
        增加gresip
        :param ip: gre sip
        :return
        """
        self._handle_gre_sip(sip, "add")

    def delete_gre_sip(self, sip):
        """
        删除代答arp
        :param sip: gre sip
        :return
        """
        self._handle_gre_sip(sip, "delete")

    def add_gre_sips(self, sip_start, sip_end):
        """
        批量增加gresips
        :param sip_start: gre sip 起始
        :param sip_start: gre sip 终止
        :return
        """
        self.offline()
        for ip in range(ip_to_int(sip_start), ip_to_int(sip_end) + 1):
            self.add_gre_sip(int_to_ip(ip))

    def del_gre_sips(self, sip_start, sip_end):
        """
        批量删除gresips
        :param sip_start: gre sip 起始
        :param sip_start: gre sip 终止
        :return
        """
        self.offline()
        for ip in range(ip_to_int(sip_start), ip_to_int(sip_end) + 1):
            self.delete_gre_sip(int_to_ip(ip))

    def get_all_gre_ips(self):
        """
        查询所有的gre ipset
        """
        gre_ips = []
        grpc_ret = self.ntb_grpc_client.grpc_call("getAllGreSip", {})
        self.assert_("get all greips faild", grpc_ret["result"]["info"] == "success")
        for gre_ip in grpc_ret["greSips"]:
            _, ip = self._parse_ipaddr_dict(gre_ip)
            gre_ips.append(ip)
        return gre_ips

    def clear_all_gre_ips(self):
        """
        清空设备上所有的gre ipset
        """
        self.offline()
        gre_ips = self.get_all_gre_ips()
        for ip in gre_ips:
            self.delete_gre_sip(ip)

    # ----setVrfGreVersion/unsetVrfGreVersion/setGlobalGreVersion/unsetGlobalGreVersion grpc----#
    def set_global_gre_version(self, version):
        """
        全局设置gre version
        params version: gre version 0/1
        return: 
        """
        grpc_ret = None
        if version == 0:
            grpc_ret = self.ntb_grpc_client.grpc_call("unsetGlobalGreVersion", {})
        else:
            grpc_ret = self.ntb_grpc_client.grpc_call("setGlobalGreVersion", {})
        self.assert_("set global gre version to %d faild" % (version), grpc_ret["info"] == "success")

    def set_vrf_gre_version(self, vrfname, version):
        """
        基于vrf 设置gre version
        params vrfname: vrf name
        params version: gre version
        return: None
        """
        grpc_ret = None
        if version == 0:
            grpc_ret = self.ntb_grpc_client.grpc_call("unsetVrfGreVersion", {"vrfName": vrfname})
        else:
            grpc_ret = self.ntb_grpc_client.grpc_call("setVrfGreVersion", {"vrfName": vrfname})
        self.assert_("set vrf %s gre version to %d faild" % (vrfname, version), grpc_ret["info"] == "success")

    def set_confcheck_rpc_limit(self, max_num):
        """
        设置配置核查接口并发数量
        params max_num: confcheck max rpc num
        return: None
        """
        grpc_ret = None
        grpc_ret = self.ntb_grpc_client.grpc_call("setConfCheckRPCMaxNum", {"max_num": max_num})
        self.assert_("set confcheck_rpc_limit to %d faild" % (max_num), grpc_ret["info"] == "success")

    def get_confcheck_rpc_limit(self):
        """
        获取配置核查接口并发数量
        return: max_num
        """
        grpc_ret = None
        grpc_ret = self.ntb_grpc_client.grpc_call("getConfCheckRPCMaxNum", {})
        self.assert_("get confcheck_rpc_limit faild", grpc_ret["result"]["info"] == "success")
        return grpc_ret["max_num"], grpc_ret["current_num"]

    # def handle_confcheck(self, vrfname, expect_cancelled, cfgtypes):
    #     statuscode = self.ntb_grpc_client.ntb_confcheck(vrfname, cfgtypes)
    #     if expect_cancelled and statuscode != grpc.StatusCode.CANCELLED:
    #         self.fail("grpc call's return status is not CANCELLED, code=%s" % statuscode)
    #         return 
    #     if (not expect_cancelled) and statuscode != grpc.StatusCode.OK:
    #         self.fail("grpc call's return status is not OK, code=%s" % statuscode)
    #         return
    def handle_confcheck(self, vrfname, cfgtypes):
        statuscode = self.ntb_grpc_client.ntb_confcheck(vrfname, cfgtypes)
        if statuscode == grpc.StatusCode.CANCELLED:
            self.cancel_count = self.cancel_count + 1
        if statuscode == grpc.StatusCode.OK:
            self.success_count = self.success_count + 1

    # --------------------------------getVrfBriefInfos-----------------------------------------------#
    def get_vrf_brief_info(self):
        """
        获取vrf的概要信息
        """
        vrf_brief_map = {}
        grpc_ret = self.ntb_grpc_client.grpc_call("getVrfBriefInfos", {})
        self.assert_("get vrf brief faild", grpc_ret["result"]["info"] == "success")
        for entry in grpc_ret["vrfBriefInfos"]:
            vrfname = entry["vrfName"]
            vrf_brief_map[vrfname] = []
            vrf_brief_map[vrfname].append(entry)
        return vrf_brief_map

     
    def get_hw_table_spec(self):
        """
        获取硬件表项规格
        """
        hw_table_map = {}
        grpc_ret = self.ntb_grpc_client.grpc_call("getHWTableSpec", {})
        self.assert_("get hw table spec faild", grpc_ret["result"]["info"] == "success")
        for entry in grpc_ret["hwTableSpecs"]:
            tablename = entry["tableName"]
            hw_table_map[tablename] = entry
        return hw_table_map

    def get_swf_memory_stat(self):
        """
        获取dpdk内存统计:
        {'result': {'info': 'success', 'code': 0}, 'swfMemStats': [{'total_bytes': 2147483648, 'free_bytes': 1350450560, 'alloc_bytes': 797033088, 'nodeid': 0}], 'MAX_GRPC_COST': 20.855926275253296}
        """
        mem_stat_map = {}
        grpc_ret = self.ntb_grpc_client.grpc_call("getSwfMemStats", {})
        self.assert_("get swf memory stat faild", grpc_ret["result"]["info"] == "success")
        mem_stat_map = grpc_ret["swfMemStats"]
        print("total_bytes: {} free_bytes: {} alloc_bytes: {}".format(mem_stat_map[0]["total_bytes"], mem_stat_map[0]["free_bytes"], mem_stat_map[0]["alloc_bytes"]))
        return mem_stat_map[0]["total_bytes"], mem_stat_map[0]["free_bytes"], mem_stat_map[0]["alloc_bytes"]

    def check_swf_memory_leak(self, total_bytes, free_bytes, alloc_bytes):
        """
        检查dpdk内存是否泄漏
        """
        new_total_bytes, new_free_bytes, new_alloc_bytes = self.get_swf_memory_stat()
        self.assert_("swf memory total_bytes changed", total_bytes == new_total_bytes)
        self.assert_("swf memory free_bytes decreased", free_bytes == new_free_bytes)
        self.assert_("swf memory alloc_bytes increased", alloc_bytes == new_alloc_bytes)
        return True

    def config_capture_start(self, vrfname, tuples_info, packetnum, ttl_start, ttl_end, both):
        """
        开启抓包
        """
        sip = {}
        dip = {}
        rule = {}
        sip_info = tuples_info["srcip"].split("/")
        dip_info = tuples_info["dstip"].split("/")
        if len(sip_info) == 2:
            sip = self._encap_prefix_item(sip_info[0], int(sip_info[1]), "ipv4")
        else:
            sip = self._encap_ip_item(sip_info[0], "ipv4")

        if len(dip_info) == 2:
            dip = self._encap_prefix_item(dip_info[0], int(dip_info[1]), "ipv4")
        else:
            dip = self._encap_ip_item(dip_info[0], "ipv4")

        rule["srcip"] = sip
        rule["dstip"] = dip
        rule["vrfname"] = vrfname
        rule["srcport"] = tuples_info["srcport"]
        rule["dstport"] = tuples_info["dstport"]
        rule["proto"] = tuples_info["proto"]
        rule["packetnum"] = packetnum
        rule["ttl_start"] = ttl_start
        rule["ttl_end"] = ttl_end
        rule["is_both"] = both

        grpc_ret = self.ntb_grpc_client.grpc_call("startCapture", rule)
        self.assert_("start capture failed", grpc_ret["info"] == "success")

    def config_capture_stop(self):
        """
        关闭抓包
        """
        grpc_ret = self.ntb_grpc_client.grpc_call("stopCapture", {})
        res = grpc_ret["info"] == "success" or grpc_ret["info"] == "ntb capture already stop!"
        self.assert_("stop capture failed", res)

    def check_capture_status(self, exp=True):
        """
        检查抓包状态
        """
        grpc_ret = self.ntb_grpc_client.grpc_call("getCaptureStatus", {})
        rx_pkts = int(grpc_ret["capturepacketresult"]["rxPackets"])
        tx_pkts = int(grpc_ret["capturepacketresult"]["txPackets"])
        print("Sent %d pkts, rx captured %d pkts, tx captured %d pkts."%(exp, rx_pkts, tx_pkts))
        if exp:
            self.assert_("check capture packets failed", exp == rx_pkts)
            self.assert_("check capture packets failed", exp == tx_pkts)
        return rx_pkts, tx_pkts

    def _handle_acl_statis_filter(self, vrfname, tuples_info, ttl_start, ttl_end, opt, eth_type="any"):
        sip = {}
        dip = {}
        rule = {}
        sip_info = tuples_info["srcip"].split("/")
        dip_info = tuples_info["dstip"].split("/")
        if len(sip_info) == 2:
            sip = self._encap_prefix_item(sip_info[0], int(sip_info[1]), "ipv4")
        else:
            sip = self._encap_ip_item(sip_info[0], "ipv4")

        if len(dip_info) == 2:
            dip = self._encap_prefix_item(dip_info[0], int(dip_info[1]), "ipv4")
        else:
            dip = self._encap_ip_item(dip_info[0], "ipv4")

        rule["srcip"] = sip
        rule["dstip"] = dip
        rule["vrfname"] = vrfname
        rule["srcport"] = tuples_info["srcport"]
        rule["dstport"] = tuples_info["dstport"]
        rule["proto"] = tuples_info["proto"]
        rule["ttl_start"] = ttl_start
        rule["ttl_end"] = ttl_end
        if eth_type == "any":
            rule["mac_type"] = 0
        elif eth_type == "lldp":
            rule["mac_type"] = 0x88cc
        elif eth_type == "lacp":
            rule["mac_type"] = 0x8809
        elif eth_type == "arp":
            rule["mac_type"] = 0x0806

        if opt == "add":
            grpc_ret = self.ntb_grpc_client.grpc_call("addStatisFiterRule", rule)
            self.assert_("add acl statis rule failed", grpc_ret["info"] == "success")
        elif opt == "del":
            grpc_ret = self.ntb_grpc_client.grpc_call("delStatisFiterRule", rule)
            self.assert_("del acl statis rule failed", grpc_ret["info"] == "success")

    def add_acl_statis_filter(self, vrfname, sip, dip, sport, dport, proto, eth_type="any"):
        """
        添加acl流统规则
        param vrfname: vrf名称
        param sip: 源ip, eg: 10.10.1.1/32
        param dip: 源ip, eg: 10.10.1.1/32
        param sport: 源端口
        param dport: 目的端口
        param proto: 协议号, icmp,tcp,udp
        """
        tuples_info = {}
        tuples_info["srcip"] = "0.0.0.0/0"
        tuples_info["dstip"] = "0.0.0.0/0"
        tuples_info["srcport"] = 0
        tuples_info["dstport"] = 0
        tuples_info["proto"] = 0
        if sip != "":
            tuples_info["srcip"] = sip
        if dip != "":
            tuples_info["dstip"] = dip
        if sport != 0:
            tuples_info["srcport"] = sport
        if dport != 0:
            tuples_info["dstport"] = dport
        if proto == "icmp":
            tuples_info["proto"] = 1
        elif proto == "udp":
            tuples_info["proto"] = 17
        elif proto == "tcp":
            tuples_info["proto"] = 6
        elif proto == "icmpv6":
            tuples_info["proto"] = 58
        self._handle_acl_statis_filter(vrfname, tuples_info, 0, 255, "add", eth_type)

    def del_acl_statis_filter(self, vrfname, sip, dip, sport, dport, proto, eth_type="any"):
        """
        删除acl流统规则
        param vrfname: vrf名称
        param sip: 源ip, eg: 10.10.1.1/32
        param dip: 源ip, eg: 10.10.1.1/32
        param sport: 源端口
        param dport: 目的端口
        param proto: 协议号, icmp,tcp,udp
        """
        tuples_info = {}
        tuples_info["srcip"] = "0.0.0.0/0"
        tuples_info["dstip"] = "0.0.0.0/0"
        tuples_info["srcport"] = 0
        tuples_info["dstport"] = 0
        tuples_info["proto"] = 0
        if sip != "":
            tuples_info["srcip"] = sip
        if dip != "":
            tuples_info["dstip"] = dip
        if sport != 0:
            tuples_info["srcport"] = sport
        if dport != 0:
            tuples_info["dstport"] = dport
        if proto == "icmp":
            tuples_info["proto"] = 1
        elif proto == "udp":
            tuples_info["proto"] = 17
        elif proto == "tcp":
            tuples_info["proto"] = 6
        elif proto == "icmpv6":
            tuples_info["proto"] = 58

        self._handle_acl_statis_filter(vrfname, tuples_info, 0, 255, "del", eth_type)

    def get_acl_statis(self):
        """
        获取acl流统数据
        """
        acl_stat_map = {}
        grpc_ret = self.ntb_grpc_client.grpc_call("lookStatisFiterAll", {})
        index = 0
        for rule in grpc_ret["statisfiterdesc"]:
            vrfname = rule["vrfname"]
            acl_stat = grpc_ret["statispacketresult"][index]
            direction = acl_stat["rtDirect"]
            key = "%s-%d" % (vrfname, direction)
            acl_stat_map[key] = acl_stat
            index += 1
        return acl_stat_map

    def check_acl_statis(self, exp):
        """
        检查acl流统数量
        """
        grpc_ret = self.ntb_grpc_client.grpc_call("lookStatisFiterAll", {})
        statis_ret = grpc_ret["statispacketresult"]
        rx_pkts = statis_ret[0]["rtPackets"]
        tx_pkts = statis_ret[1]["rtPackets"]
        self.assert_("check statis rule failed", rx_pkts == exp)
        self.assert_("check statis rule failed", tx_pkts == exp)

    def check_loop(self, cmd, string, message, times=10):
        flag = 0
        while True:
            output, _ = self.ntb_ssh_client.exec_cmd(cmd)
            result = str(output, 'UTF-8')
            self.log_info(result)
            checkres = utils.singleStrPattern(string, result)
            time.sleep(1)
            if flag > times or checkres:
                break
            flag += 1
        self.assert_(message, checkres)
        return checkres

    def down_neighbor(self, bgpid, neighbor):
        cmd = "vtysh -c \"c t\" -c \" router bgp %d\" -c \" neighbor %s shutdown\"" % (bgpid, neighbor)
        res_cli, _ = self.ntb_ssh_client.exec_cmd(cmd)

    def up_neighbor(self, bgpid, neighbor):
        cmd = "vtysh -c \"c t\" -c \" router bgp %d\" -c \"no neighbor %s shutdown\"" % (bgpid, neighbor)
        res_cli, _ = self.ntb_ssh_client.exec_cmd(cmd)

    def kill_process(self, process_name):

        cmd = "ps -ef|grep %s |grep -v grep" % process_name
        res_cli, err = self.ntb_ssh_client.exec_cmd(cmd)
        res_cli_str = str(res_cli, encoding='utf-8')
        self.log_info(res_cli_str)
        for line in res_cli_str.splitlines():
            pid = line.split()[1]
            self.ntb_ssh_client.exec_cmd('kill -9 %s' % pid)

    def kill_docker_process(self, process_name):
        cmd = "docker exec -i ntb pkill -9 " % process_name
        res_cli, err = self.ntb_ssh_client.exec_cmd(cmd)
        res_cli_str = str(res_cli)
        self.log_info(res_cli)
        self.log_info(err)

    def check_write_ov_cfg_status(self, tsc):
        grpc_ret = self.ntb_grpc_client.grpc_call("queryVrfConfig", {"tsc": tsc})
        save_status = grpc_ret["writeVrfCfgStatus"]["result"]
        return save_status

    def save_ov_cfg(self):
        grpc_ret = self.ntb_grpc_client.grpc_call("writeVrfConfig", {})
        self.log_info(grpc_ret)
        tsc = grpc_ret["writeVrfCfgTsc"]["tsc"]
        for i in range(0, 10):
            if not self.check_write_ov_cfg_status(tsc):
                return
            time.sleep(1)
        self.assert_("save cfg not finish", not self.check_write_ov_cfg_status(tsc))

    def up_underlay(self, underlay_neigh):
        cmd = "iptables -D INPUT -s %s -j DROP" % underlay_neigh
        res_cli, _ = self.ntb_ssh_client.exec_cmd(cmd)

    def down_underlay(self, underlay_neigh):
        cmd = "iptables -I INPUT -s %s -j DROP" % underlay_neigh
        res_cli, _ = self.ntb_ssh_client.exec_cmd(cmd)

    def get_hw_spec(self, table=""):
        if table == "":
            cmd = "show ntb hw table spec"
        else:
            cmd = "show ntb hw table spec|grep %s" % table
        res_cli, _ = self.ntb_ssh_client.exec_cmd(cmd)
        res = str(res_cli, encoding='utf-8').split()
        self.log_info(res)
        print(res)
        if table == "":
            return 0, 0
        return int(res[1]), int(res[2])

    def handle_encap_annsis(self, hash_num,proto):
        pcap_package = rdpcap("%s/%s-capture.pcap0" % (settings.ROOT_PATH, settings.NTB_CNTL_VIP))
        vpc_id_list =[]
        vni_list = []
        if proto=='vxlan':
            for data in pcap_package:
                if data["IP"].proto == 17:
                    vni_list.append(data['VXLAN'].vni)
            count = Counter(vni_list)
            if (int(hash_num * 0.5) < (len(count))) and (count.most_common(1)[0][1] <= 4) and (
                    vni_list.__len__() == hash_num):
                return True
            else:
                return False
        elif proto=='gre':
            for data in pcap_package:
                if data["IP"].proto == 47:
                    vpc_id_list.append(data['GRE'].key)
            count = Counter(vpc_id_list)
            print(count)
            if (int(hash_num * 0.5) < (len(count))) and (count.most_common(1)[0][1] <= 4) and (
                    vpc_id_list.__len__() == hash_num):
                return True
            else:
                return False
        else:
            return False
        
    # -------------------------------create sflow/delete sflow grpc---------------------------------------------------#
    def _check_sflow_res(self, op, res, expect_res):
        for sflow in res:
            vrf = sflow['sflowInfo']['vrf']['vrfName']
            e_res = expect_res[vrf]
            in_device_cfgs = self.ntb_grpc_client.get_ntb_vrf_config(vrf, ["sflow"])
            sflow_exist_in_devce = False
            if 'sflow' in in_device_cfgs:
                sflow_exist_in_devce = True
            
            if op == "create":
                if e_res == "success":
                    if e_res != sflow["result"]["info"]:
                        self.log_info(
                            "%s sflow %s result not expected, expect %s but %s" % (op, vrf, e_res, sflow["result"]["info"]))
                        return False
                    if not sflow_exist_in_devce:
                        self.log_info("%s %s sflow success, but not set in device" % (op, vrf))
                        return False
                    if sflow['sflowInfo']["serviceType"] != in_device_cfgs['sflow']['serviceType'] or \
                            sflow['sflowInfo']["serviceId"] != in_device_cfgs['sflow']['serviceId'] or \
                            sflow['sflowInfo']["action"] != in_device_cfgs['sflow']['action']:
                        self.log_info("%s %s sflow success, but %s inconsitent with %s in device" %
                                    (op, vrf, str(sflow['sflowInfo']), str(in_device_cfgs['sflow'])))
                        return False
            else:
                if e_res == "success":
                    if e_res != sflow["result"]["info"]:
                        self.log_info(
                            "%s sflow %s result not expected, expect %s but %s" % (op, vrf, e_res, sflow["result"]["info"]))
                        return False
                    if sflow_exist_in_devce:
                        self.log_info("%s %s sflow success, but still set in device" % (op, vrf))
                        return False
        return True

    def _handle_sflow(self, sflow_list, op, check=True):
        """
        下发sflow配置
        """
        if len(sflow_list) == 0:
            return
        dict_request = {
            "sflowInfos":[]
        }

        expect_res = {}
        for sflow in sflow_list:
            item = {}
            item['serviceType'] = sflow['serviceType']
            item['serviceId'] = sflow['serviceId']
            item['action'] = sflow['action']
            vrf = {}
            vrf['vrfName'] = sflow['vrf']
            item['vrf'] = vrf
            dict_request["sflowInfos"].append(item)

            expect_key = vrf['vrfName']
            if "expect_res" not in sflow:
                sflow["expect_res"] = "success"
            expect_res[expect_key] = sflow["expect_res"]

        grpc_ret = None
        if op == "create":
            grpc_ret = self.ntb_grpc_client.grpc_call("addVrfSflow", dict_request)
        else:
            grpc_ret = self.ntb_grpc_client.grpc_call("delVrfSflow", dict_request)

        if check:
            self.assert_("%s sflow faild, not expected" % (op),
                     self._check_sflow_res(op, grpc_ret["sflowInfoCfgs"], expect_res))
        else:
            self.assert_("%s sflow faild, not expected" % (op), (grpc_ret["result"]["info"] == "success"))

    def create_sflow(self, sflow_list, check=True):
        """
        创建sflow 
        :param vrfname: vrf name
        :param sflow_list: sflow列表
            item: eg: {"vrf":'vrfname', "serviceType":1, "serviceId":12, "action":"accept"}
        :return
        """
        self._handle_sflow(sflow_list, "create", check)

    def delete_sflow(self, sflow_list, check=True):
        """
        删除sflow 
        :param vrfname: vrf name
        :param sflow_list: sflow列表
            item: eg: {"vrf":'vrfname', "serviceType":1, "serviceId":12, "action":"accept"}
        :return
        """
        self._handle_sflow(sflow_list, "delete", check)

    def _check_sflow_res(self, op, res, expect_res):
        for sflow in res:
            vrf = sflow['sflowInfo']['vrf']['vrfName']
            e_res = expect_res[vrf]
            in_device_cfgs = self.ntb_grpc_client.get_ntb_vrf_config(vrf, ["sflow"])
            sflow_exist_in_devce = False
            if 'sflow' in in_device_cfgs:
                sflow_exist_in_devce = True
            
            if op == "create":
                if e_res == "success":
                    if e_res != sflow["result"]["info"]:
                        self.log_info(
                            "%s sflow %s result not expected, expect %s but %s" % (op, vrf, e_res, sflow["result"]["info"]))
                        return False
                    if not sflow_exist_in_devce:
                        self.log_info("%s %s sflow success, but not set in device" % (op, vrf))
                        return False
                    if sflow['sflowInfo']["serviceType"] != in_device_cfgs['sflow']['serviceType'] or \
                            sflow['sflowInfo']["serviceId"] != in_device_cfgs['sflow']['serviceId'] or \
                            sflow['sflowInfo']["action"] != in_device_cfgs['sflow']['action']:
                        self.log_info("%s %s sflow success, but %s inconsitent with %s in device" %
                                    (op, vrf, str(sflow['sflowInfo']), str(in_device_cfgs['sflow'])))
                        return False
            else:
                if e_res == "success":
                    if e_res != sflow["result"]["info"]:
                        self.log_info(
                            "%s sflow %s result not expected, expect %s but %s" % (op, vrf, e_res, sflow["result"]["info"]))
                        return False
                    if sflow_exist_in_devce:
                        self.log_info("%s %s sflow success, but still set in device" % (op, vrf))
                        return False
        return True

    def _handle_sflow_reportip(self, reportip, op):
        """
        下发sflow report配置
        """
        dict_request = {}
        if "agentAddr" in reportip:
            dict_request["agentAddr"] = self._encap_ip_item(reportip["agentAddr"], "ipv4")
        if "collectorAddr" in reportip:
            dict_request["collectorAddr"] = self._encap_ip_item(reportip["collectorAddr"], "ipv4")

        if 'expect_res' not in reportip:
            expect_res = "success"
        else:
            expect_res = reportip['expect_res']

        grpc_ret = None
        if op == "create":
            grpc_ret = self.ntb_grpc_client.grpc_call("setSflowReportIp", dict_request)
        else:
            grpc_ret = self.ntb_grpc_client.grpc_call("unsetSflowReportIp", dict_request)
        self.assert_("%s sflow reportip faild" % (op, ), grpc_ret["info"] == expect_res)

    def create_sflow_reportip(self, reportip):
        """
        创建sflow reportip
        reportip: eg: {
            "agentAddr": "10.0.0.0",
            "collectorAddr": "20.0.0.0"
            }
        :return
        """
        self._handle_sflow_reportip(reportip, "create")

    def delete_sflow_reportip(self, reportip):
        """
        删除sflow reportip
        :param 
        reportip: eg: {
            "agentAddr": "10.0.0.0",
            "collectorAddr": "20.0.0.0"
            }
        :return
        """
        self._handle_sflow_reportip(reportip, "delete")

    def _check_vni_mtu_res(self, vrfname, op, res, expect_res):
        in_device_vni_mtu_cfgs = {}
        cfgtypes = ["vniMtuInfos"]
        in_device_cfgs = self.ntb_grpc_client.get_ntb_vrf_config(vrfname, cfgtypes)
        for vni_mtu in in_device_cfgs["vniMtuInfos"]:
            vni = vni_mtu["vni"]
            mtu = vni_mtu["mtu"]
            in_device_vni_mtu_cfgs[vni] = mtu

        for item in res:
            key = item['vniMtuInfo']["vni"]
            value = item['vniMtuInfo']["mtu"]
            e_res = expect_res[key]
            if e_res != item["result"]["info"]:
                self.log_info("%s vni mtu %s result not expected, expect %s but %s" % (
                    op, key, e_res, item["result"]["info"]))
                return False
            if op == "create":
                if e_res == "success":
                    if key not in in_device_vni_mtu_cfgs:
                        self.log_info("%s vni mtu  %s success, but not set in device" % (op, key))
                        return False
                    if in_device_vni_mtu_cfgs[key] != value:
                        self.log_info("%s vni mtu  %s success, but %s inconsitent with %s in device" %
                                      (op, key, str(value), str(in_device_vni_mtu_cfgs[key])))
                        return False
            else:
                if e_res == "success":
                    if key in in_device_vni_mtu_cfgs:
                        self.log_info("%s vni mtu  %s success, but still in device" % (op, key))
                        return False
        return True

    def _handle_vni_mtu(self, vrfname, vni_mtu_list, op):
        """
        下发vni mtu配置
        """
        if len(vni_mtu_list) == 0:
            return
        dict_request = {
            "vrf": {
                "vrfName": vrfname
            },
            "vniMtuInfo": [
            ]
        }

        expect_res = {}
        for index in range(len(vni_mtu_list)):
            vni_mtu = vni_mtu_list[index]
            item = {}
            item["vni"] = vni_mtu['vni']
            item["mtu"] = vni_mtu['mtu']
            dict_request["vniMtuInfo"].append(item)
            if "expect_res" in vni_mtu:
                expect_res[item["vni"]] = vni_mtu["expect_res"]
            else:
                expect_res[item["vni"]] = "success"
            if (index + 1) % 20000 == 0:
                grpc_ret = None
                if op == "create":
                    grpc_ret = self.ntb_grpc_client.grpc_call("addVrfVniMtu", dict_request)
                else:
                    grpc_ret = self.ntb_grpc_client.grpc_call("delVrfVniMtu", dict_request)

                self.assert_("%s vni mtu faild, not expected" % (op),
                             self._check_vni_mtu_res(vrfname, op, grpc_ret["vniMtuCfgs"], expect_res))
                expect_res = {}
                dict_request["vniMtuInfo"].clear()
        if len(dict_request["vniMtuInfo"]) > 0:
            grpc_ret = None
            if op == "create":
                grpc_ret = self.ntb_grpc_client.grpc_call("addVrfVniMtu", dict_request)
            else:
                grpc_ret = self.ntb_grpc_client.grpc_call("delVrfVniMtu", dict_request)
            self.assert_("%s vni mtu faild, not expected" % (op),
                         self._check_vni_mtu_res(vrfname, op, grpc_ret["vniMtuCfgs"], expect_res))

    def create_vni_mtu(self, vrfname, vni_mtu_list):
        """
        创建vni mtu
        :param vrfname: vrf name
        :param vni_mtu_list: vni mtu信息列表
            item: eg: {"vni": 1001, "mtu": 1500, "expect_res": "success"}
        :return
        """
        self._handle_vni_mtu(vrfname, vni_mtu_list, "create")

    def delete_vni_mtu(self, vrfname, vni_mtu_list):
        """
        删除vni mtu
        :param vrfname: vrf name
        :param vni_mtu_list: vni mtu信息列表
            item: eg: {"vni": 1001, "mtu": 1500, "expect_res": "success"}
        :return
        """
        self._handle_vni_mtu(vrfname, vni_mtu_list, "delete")

    def get_vni_mtu(self, vrfname):
        in_device_vni_mtu_cfgs = {}
        cfgtypes = ["vniMtuInfos"]
        in_device_cfgs = self.ntb_grpc_client.get_ntb_vrf_config(vrfname, cfgtypes)
        for vni_mtu in in_device_cfgs["vniMtuInfos"]:
            vni = vni_mtu["vni"]
            mtu = vni_mtu["mtu"]
            in_device_vni_mtu_cfgs[vni] = mtu
        return in_device_vni_mtu_cfgs

    '''
    这个接口当前获取到的vni下一跳mtu是错误的
    def get_vxlan_nexthop_mtu(self, vxlan_nexthop_list):
        """
        获取vxlan nexthop mtu
        :param vxlan_nexthop_mtu_list: vxlan nexthop mtu信息列表
            item: eg: {"nexthop": "1.1.1.1", "vni": 100}
        :return
        """
        mtu_infos = {}
        if len(vxlan_nexthop_list) == 0:
            return

        dict_request = {
            "vxlanNexthopMtus": []
        }
        for index in range(len(vxlan_nexthop_list)):
            vxlan_nh_info = vxlan_nexthop_list[index]
            item = {}
            item["nexthopIp"] = self._encap_ip_item(vxlan_nh_info["nexthop"], "ipv4")
            item["vni"] = vxlan_nh_info["vni"]
            if "gateway" not in vxlan_nh_info:
                vxlan_nh_info["gateway"] = "0.0.0.0"
            item["gateway"] = self._encap_ip_item(vxlan_nh_info["gateway"], "ipv4")
            dict_request["vxlanNexthopMtus"].append(item)
        grpc_ret = self.ntb_grpc_client.grpc_call("getVxlanNexthopMtu", dict_request)
        self.assert_("get vxlan nexthop mtu faild", grpc_ret["result"]["info"] == "success")
        for item in grpc_ret["vxlanNexthopMtuCfgResults"]:
            _, nip = self._parse_ipaddr_dict(item["vxlanNexthopMtu"]["nexthopIp"])
            vni = item["vxlanNexthopMtu"]["vni"]
            mtu = item["vxlanNexthopMtu"]["mtu"] 
            key = "%s-%d" % (nip, vni)
            mtu_infos[key] = mtu 
        return mtu_infos
    '''

    def check_vrf_tunnel_mtu(self, op, vrf, mtu=0):
        grpc_ret = self.ntb_grpc_client.grpc_call("getVrfTunnelMtu", {'vrf':vrf})
        if op == 'create':
            for i in grpc_ret['tunnel_mtu_info']:
                tun_type='vxlan' if i['tunnel_type']==0 else 'gre'
                tmp_mtu = mtu
                if mtu == 0:
                    if tun_type == "vxlan":
                        tmp_mtu = 1500
                    else:
                        tmp_mtu = 1468
                if i['mtu'] != tmp_mtu:
                    self.log_info("%s vrf mtu %s faild, tunnel %s %s mtu %s in device is not expected" % 
                                  (op, tmp_mtu, tun_type, i['tunnel_id'], i['mtu']))
                    return False
        else:
            for i in grpc_ret['tunnel_mtu_info']:
                tun_type='vxlan' if i['tunnel_type']==0 else 'gre'
                tun_mtu=1500 if i['tunnel_type']==0 else 1468
                if i['mtu'] != tun_mtu:
                    self.log_info("%s vrf mtu %s faild, tunnel %s %s mtu %s in device is not expected" % 
                                  (op, mtu, tun_type, i['tunnel_id'], i['mtu']))
                    return False
        return True

    def _check_vrf_mtu_res(self, op, res, expect_res):
        in_device_vrf_mtu_cfgs = {}
        cfgtypes = ["vrfMtuInfo"]
        for i in res:
            vrfname = i["vrfMtuInfo"]['vrf']['vrfName']
            mtu = i["vrfMtuInfo"]['mtu']
            in_device_cfgs = self.ntb_grpc_client.get_ntb_vrf_config(vrfname, cfgtypes)
            in_device_vrf_mtu_cfgs[vrfname] = in_device_cfgs['vrfMtuInfo']['mtu']

            e_res = expect_res[vrfname]
            if e_res != i["result"]["info"]:
                self.log_info("%s vrf mtu %s result not expected, expect %s but %s" % (
                    op, vrfname, e_res, i["result"]["info"]))
                return False
            if op == "create":
                if e_res == "success":
                    if vrfname not in in_device_vrf_mtu_cfgs:
                        self.log_info("%s vrf mtu  %s success, but not set in device" % (op, vrfname))
                        return False
                    if in_device_vrf_mtu_cfgs[vrfname] != mtu:
                        self.log_info("%s vrf mtu  %s success, but %s inconsitent with %s in device" %
                                      (op, vrfname, str(mtu), str(in_device_vrf_mtu_cfgs[vrfname])))
                        return False
                    if not self.check_vrf_tunnel_mtu(op, vrfname, mtu):
                        return False
            else:
                if e_res == "success":
                    if vrfname in in_device_vrf_mtu_cfgs and in_device_vrf_mtu_cfgs[vrfname] != 0:
                        self.log_info("%s vrf mtu  %s success, but still in device" % (op, vrfname))
                        return False
                    if not self.check_vrf_tunnel_mtu(op, vrfname, mtu):
                        return False
        return True

    def _handle_vrf_mtu(self, vrf_mtu_list, op, check=True):
        """
        下发vni mtu配置
        """
        if len(vrf_mtu_list) == 0:
            return
        dict_request = {
            "vrfMtuInfos": [
            ]
        }

        expect_res = {}
        for index in range(len(vrf_mtu_list)):
            vrf_mtu = vrf_mtu_list[index]
            item = {}
            item["vrf"] = {}
            item["vrf"]["vrfName"] = vrf_mtu['vrf']
            item["mtu"] = vrf_mtu['mtu']
            dict_request["vrfMtuInfos"].append(item)
            if "expect_res" in vrf_mtu:
                expect_res[item["vrf"]["vrfName"]] = vrf_mtu["expect_res"]
            else:
                expect_res[item["vrf"]["vrfName"]] = "success"
            if (index + 1) % 20000 == 0:
                grpc_ret = None
                if op == "create":
                    grpc_ret = self.ntb_grpc_client.grpc_call("addVrfMtu", dict_request)
                else:
                    grpc_ret = self.ntb_grpc_client.grpc_call("delVrfMtu", dict_request)

                if check:
                    self.assert_("%s vrf mtu faild, not expected" % (op),
                                self._check_vrf_mtu_res(op, grpc_ret["vrfMtuCfgs"], expect_res))
                else:
                    self.assert_("%s vrf mtu faild, not expected" % (op),
                                grpc_ret["result"]['info'] == 'success')
                expect_res = {}
                dict_request["vrfMtuInfos"].clear()
        if len(dict_request["vrfMtuInfos"]) > 0:
            grpc_ret = None
            if op == "create":
                grpc_ret = self.ntb_grpc_client.grpc_call("addVrfMtu", dict_request)
            else:
                grpc_ret = self.ntb_grpc_client.grpc_call("delVrfMtu", dict_request)
            if check:
                self.assert_("%s vrf mtu faild, not expected" % (op),
                            self._check_vrf_mtu_res(op, grpc_ret["vrfMtuCfgs"], expect_res))
            else:
                self.assert_("%s vrf mtu faild, not expected" % (op),
                            grpc_ret["result"]['info'] == 'success')

    def create_vrf_mtu(self, vrf_mtu_list, check=True):
        """
        创建vrf mtu
        :param vrf_mtu_list: vrf mtu信息列表
            item: eg: {"vrf": vrf1, "mtu": 1500, "expect_res": "success"}
        :return
        """
        self._handle_vrf_mtu(vrf_mtu_list, "create", check)

    def delete_vrf_mtu(self, vrf_mtu_list, check=True):
        """
        创建vrf mtu
        :param vrf_mtu_list: vrf mtu信息列表
            item: eg: {"vrf": vrf1, "mtu": 1500, "expect_res": "success"}
        :return
        """
        self._handle_vrf_mtu(vrf_mtu_list, "delete", check)
    
    def get_gre_nexthop_mtu(self, gre_nexthop_list):
        """
        获取gre nexthop mtu
        :param gre_nexthop_mtu_list: gre nexthop mtu信息列表
            item: eg: {"nexthop": "1.1.1.1", "vpcid": 100}
        :return
        """
        mtu_infos = {}
        if len(gre_nexthop_list) == 0:
            return

        dict_request = {
            "greNexthopMtus": []
        }
        for index in range(len(gre_nexthop_list)):
            gre_nh_info = gre_nexthop_list[index]
            item = {}
            item["nexthopIp"] = self._encap_ip_item(gre_nh_info["nexthop"], "ipv4")
            if "vmip" not in gre_nh_info:
                gre_nh_info["vmip"] = "0.0.0.0"
            item["vmIp"] = self._encap_ip_item(gre_nh_info["vmip"], "ipv4")
            item["vpcId"] = {"id": gre_nh_info["vpcid"]}
            dict_request["greNexthopMtus"].append(item)

        grpc_ret = self.ntb_grpc_client.grpc_call("getGreNexthopMtu", dict_request)
        self.assert_("get vpc nexthop mtu faild", grpc_ret["result"]["info"] == "success")
        for item in grpc_ret["greNexthopMtuCfgResults"]:
            _, nip = self._parse_ipaddr_dict(item["greNexthopMtu"]["nexthopIp"])
            vpcid = item["greNexthopMtu"]["vpcId"]["id"]
            mtu = item["greNexthopMtu"]["mtu"] 
            key = "%s-%d" % (nip, vpcid)
            mtu_infos[key] = mtu 

        return mtu_infos

    def _handle_vpc_nexthop_mtu(self, vpc_nexthop_mtu_list, op):
        """
        下发vpc nexthop mtu配置
        """
        if len(vpc_nexthop_mtu_list) == 0:
            return
        dict_request = {
            "nexthopMtuInfo": []
        }

        expect_res = {}
        for i in vpc_nexthop_mtu_list:
            item = {}
            item["nexthopIp"] = self._encap_ip_item(i["rip"], "ipv4")
            item["mtu"] = i["mtu"]
            dict_request["nexthopMtuInfo"].append(item)
            if "expect_res" in i:
                expect_res[i["rip"]] = i["expect_res"]
            else:
                expect_res[i["rip"]] = "success"
        if op == "create":
            grpc_ret = self.ntb_grpc_client.grpc_call("addVpcNexthopMtu", dict_request)
        else:
            grpc_ret = self.ntb_grpc_client.grpc_call("delVpcNexthopMtu", dict_request)
        self.assert_("%s vpc nexthop mtu faild, not expected" % (op),
                        self._check_vpc_nexthop_mtu_res(op, grpc_ret["nexthopMtuCfgs"], expect_res))

    def _check_vpc_nexthop_mtu_res(self, op, res, expect_res):
        in_device_vpc_nexthop_mtu_cfgs = {}
        cfgtypes = ["nexthopMtuInfo"]
        in_device_cfgs = self.ntb_grpc_client.get_ntb_global_config(cfgtypes)
        for vpc_nexthop_mtu in in_device_cfgs["nexthopMtuInfo"]:
            _, key = self._parse_ipaddr_dict(vpc_nexthop_mtu["nexthopIp"])
            mtu = vpc_nexthop_mtu["mtu"]
            in_device_vpc_nexthop_mtu_cfgs[key] = mtu

        for item in res:
            _, key = self._parse_ipaddr_dict(item['nexthopMtuInfo']["nexthopIp"])
            value = item['nexthopMtuInfo']["mtu"]
            e_res = expect_res[key]
            if e_res != item["result"]["info"]:
                self.log_info("%s vpc nexthop mtu %s result not expected, expect %s but %s" % (
                    op, key, e_res, item["result"]["info"]))
                return False
            if op == "create":
                if e_res == "success":
                    if key not in in_device_vpc_nexthop_mtu_cfgs:
                        self.log_info("%s vpc nexthop mtu  %s success, but not set in device" % (op, key))
                        return False
                    if in_device_vpc_nexthop_mtu_cfgs[key] != value:
                        self.log_info("%s vpc nexthop mtu  %s success, but %s inconsitent with %s in device" %
                                      (op, key, str(value), str(in_device_vpc_nexthop_mtu_cfgs[key])))
                        return False
            else:
                if e_res == "success":
                    if key in in_device_vpc_nexthop_mtu_cfgs:
                        self.log_info("%s vpc nexthop mtu  %s success, but still in device" % (op, key))
                        return False
        return True

    def create_vpc_nexthop_mtu(self, vpc_nexthop_mtu_list):
        """
        创建vpc nexthop mtu
        :param vpc_nexthop_mtu_list: vpc nexthop mtu信息列表
            item: eg: {"rip": 1001, "mtu": 1500, "expect_res": "success"}
        :return
        """
        self._handle_vpc_nexthop_mtu(vpc_nexthop_mtu_list, "create")

    def delete_vpc_nexthop_mtu(self, vpc_nexthop_mtu_list):
        """
        删除vpc nexthop mtu
        :param vpc_nexthop_mtu_list: vpc nexthop mtu信息列表
            item: eg: {"rip": 1001, "mtu": 1500, "expect_res": "success"}
        :return
        """
        self._handle_vpc_nexthop_mtu(vpc_nexthop_mtu_list, "delete")

    def _handle_sflow_stats(self, op):
        """
        获取或清空sflow统计
        """
        grpc_ret = None
        if op == "get":
            grpc_ret = self.ntb_grpc_client.grpc_call("getSflowStat", {})
            self.assert_("%s sflow out pkt stats faild" % (op), grpc_ret["result"]["info"] == "success")
            packets_in = grpc_ret['packets_in']
            packets_out = grpc_ret['packets_out']
            return packets_in, packets_out
        else:
            grpc_ret = self.ntb_grpc_client.grpc_call("clrSflowStat", {})
            self.assert_("%s clear sflow pkt out stats faild" % (op), grpc_ret["info"] == "success")
            return None

    def get_sflow_stat(self):
        ret = self._handle_sflow_stats("get")
        return ret

    def clear_sflow_stat(self):
        ret = self._handle_sflow_stats("set")
        return ret

    def set_sflow_coalescing_status(self, status):
        dict_request = {
            "sflow_coal_status": status
        }
        grpc_ret = self.ntb_grpc_client.grpc_call("setSflowCoalStatus", dict_request)
        self.assert_("set sflow coalescing status faild", grpc_ret["info"] == "success")
        
    def get_sflow_coalescing_status(self):
        grpc_ret = self.ntb_grpc_client.grpc_call("getSflowCoalStatus", {})
        self.assert_("get sflow coalescing status faild", grpc_ret["result"]["info"] == "success")
        return grpc_ret["sflow_coal_status"]

    def set_sflow_coalescing_length(self, legnth):
        dict_request = {
            "sflow_coal_length": legnth
        }
        grpc_ret = self.ntb_grpc_client.grpc_call("setSflowCoalLength", dict_request)
        self.assert_("set sflow coalescing legnth faild", grpc_ret["info"] == "success")

    def get_sflow_coalescing_length(self):
        grpc_ret = self.ntb_grpc_client.grpc_call("getSflowCoalLength", {})
        self.assert_("get sflow coalescing length faild", grpc_ret["result"]["info"] == "success")
        return grpc_ret["sflow_coal_length"]

    def set_sflow_coal_timeout(self, timeout):
        dict_request = {
            "sflow_coal_timeout": timeout
        }
        grpc_ret = self.ntb_grpc_client.grpc_call("setSflowCoalTimeout", dict_request)
        self.assert_("set sflow coalescing timeout faild", grpc_ret["info"] == "success")

    def get_sflow_coal_timeout(self):
        grpc_ret = self.ntb_grpc_client.grpc_call("getSflowCoalTimeout", {})
        self.assert_("get sflow coalescing timeout faild", grpc_ret["result"]["info"] == "success")
        return grpc_ret["sflow_coal_timeout"]

    def set_sflow_coal_egress_port(self, sid, egressport):
        dict_request = {
            "sid": sid,
            "egressport": egressport
        }
        grpc_ret = self.ntb_grpc_client.grpc_call("setSflowCoalEgressPort", dict_request)
        self.assert_("set sflow coalescing egress port faild", grpc_ret["info"] == "success")

    def get_sflow_coal_egress_port(self):
        grpc_ret = self.ntb_grpc_client.grpc_call("getSflowCoalEgressPort", {})
        self.assert_("get sflow coalescing egress port faild", grpc_ret["info"] == "success")
        return grpc_ret["sflowcoalegressports"]

    def set_sflow_coal_sample_rate(self, vrfname, sample):
        dict_request = {
            "vrfName": vrfname,
            "sflow_sample_rate": sample
        }
        grpc_ret = self.ntb_grpc_client.grpc_call("setSflowSampleRate", dict_request)
        self.assert_("set sflow coalescing sample rate faild", grpc_ret["info"] == "success")

    def get_sflow_coal_sample_rate(self, vrfname):
        dict_request = {
            "vrfName": vrfname
        }
        grpc_ret = self.ntb_grpc_client.grpc_call("getSflowSampleRate", dict_request)
        self.assert_("set sflow coalescing sample rate faild", grpc_ret["info"] == "success")
        return grpc_ret["sflow_sample_rate"]

    def set_interface_admin_status(self, ifacename, status):
        dict_request = {
            "InterfaceInfos" : [ {
                "InterfaceName": ifacename,
                "AdminStatus": status
            }
            ]
        }
        grpc_ret = self.ntb_grpc_client.grpc_call("setInterfaceAdminStatus", dict_request)
        self.assert_("set set iface: {} admin status: {} faild".format(ifacename, status), grpc_ret["info"] == "success")

    def get_sflow_coal_egress_port(self):
        grpc_ret = self.ntb_grpc_client.grpc_call("getSflowCoalEgressPort", {})
        self.assert_("get sflow coal egress port faild", grpc_ret["result"]["info"] == "success")
        return grpc_ret["sflowcoalegressports"]
    
    def get_sflow_reportunset_stat(self):
        grpc_ret = self.ntb_grpc_client.grpc_call("getSflowReportUnsetStat", {})
        self.assert_("get sflow reportunset stat faild", grpc_ret["result"]["info"] == "success")
        return grpc_ret["packets"]

    def clr_sflow_reportunset_stat(self):
        grpc_ret = self.ntb_grpc_client.grpc_call("clrSflowReportUnsetStat", {})
        self.assert_("clear sflow reportunset stat faild", grpc_ret["info"] == "success")

    def set_copp_cfg(self, packet_type, cir, cbs):
        """
        设置copp配置
        :param packet_type: 包类型, mirror/bfd/bgp/arp/sflow
        :param cir: 速率 kbps
        :param cbs: burst大小 kbps
        :return
        """
        dict_request = {
            "packet_type": packet_type,
            "cir": cir,
            "cbs": cbs
        }
        grpc_ret = self.ntb_grpc_client.grpc_call("setCoppCfgs", dict_request)
        self.assert_("set copp cfg faild", grpc_ret["info"] == "success")

    def get_copp_cfg(self, packet_type):
        """
        设置copp配置
        :param packet_type: 包类型, mirror/bfd/bgp/arp/sflow
        :return
        """
        dict_request = {
            "packet_type": packet_type,
        }
        grpc_ret = self.ntb_grpc_client.grpc_call("getCoppCfgs", dict_request)
        self.assert_("get copp cfg faild", grpc_ret["result"]["info"] == "success")
        return grpc_ret["cir"], grpc_ret["cbs"]

    def set_sflow_meter_cfg(self, cir, cbs):
        """
        设置sflow meter配置
        :param cir: 速率 kbps
        :param cbs: burst大小 kbps
        :return
        """
        dict_request = {
            "cir": cir,
            "cbs": cbs
        }
        grpc_ret = self.ntb_grpc_client.grpc_call("setSflowMeter", dict_request)
        self.assert_("set sflow meter cfg faild", grpc_ret["info"] == "success")

    def get_sflow_meter_info(self):
        """
        获取sflow meter 信息
        :param 
        :return
        """
        dict_request = {
        }
        grpc_ret = self.ntb_grpc_client.grpc_call("getSflowMeter", dict_request)
        self.assert_("get sflow meter info faild", grpc_ret["result"]["info"] == "success")
        sflow_meter_info = {}
        sflow_meter_info["cir"] = grpc_ret["cir"] 
        sflow_meter_info["cbs"] = grpc_ret["cbs"]
        sflow_meter_info["pkts"] = grpc_ret["conform_packets"]
        sflow_meter_info["drop_pkts"] = grpc_ret["violate_packets"]
        return sflow_meter_info

    def clear_sflow_meter_stat(self):
        """
        清空sflow meter统计
        :return
        """
        dict_request = {
        }
        grpc_ret = self.ntb_grpc_client.grpc_call("clrSflowMeterStat", dict_request)
        self.assert_("clear sflow meter stat faild", grpc_ret["info"] == "success")
    
    def get_hostif_info(self):
        """
        获取hostif信息
        :return {"Eth100GE1": {ipaddr: "", gwaddr: "", gwmac:"", linkstatus: ""}}
        """
        hostif_infos = {}
        grpc_ret = self.ntb_grpc_client.grpc_call("getAllHostIfCfg", {})
        self.assert_("get hostif info faild", grpc_ret["result"]["info"] == "success")
        for ifcfg in grpc_ret["hostifCfgs"]:
            item = {}
            ifname = ifcfg["name"]
            _, ipaddr, ipaddr_len = self._parse_prefix_dict(ifcfg["ipaddr"])
            _, gwaddr, gwaddr_len = self._parse_prefix_dict(ifcfg["gwaddr"])
            gwmac = ifcfg["gwmac"]
            linkstatus = ifcfg["linkstatus"]
            item["ipaddr"] = "%s/%s" % (ipaddr, ipaddr_len)
            item["gwaddr"] = "%s/%s" % (gwaddr, gwaddr_len)
            item["gwmac"] = gwmac
            item["linkstatus"] = linkstatus
            hostif_infos[ifname] = item
        return hostif_infos

    def _check_vxlan_sport_hash_rule_res(self, vrfname, op, res, expect_res):
        in_device_cfgs = {}
        cfgtypes = ["vxlanSportHashRules"]
        in_device_cfgs = self.ntb_grpc_client.get_ntb_vrf_config(vrfname, cfgtypes)
        for sport_hash_rule in in_device_cfgs["vxlanSportHashRules"]:
            mac_type = sport_hash_rule['mac_type']
            ip_proto = sport_hash_rule['ip_proto']
            dst_port = sport_hash_rule['dst_port']
            key = "%d_%d_%d" % (mac_type, ip_proto, dst_port)
            in_device_cfgs[key] = sport_hash_rule 

        for item in res:
            mac_type = item['vxlanSportHashRule']['mac_type']
            ip_proto = item['vxlanSportHashRule']['ip_proto']
            dst_port = item['vxlanSportHashRule']['dst_port']
            key = "%d_%d_%d" % (mac_type, ip_proto, dst_port)
            e_res = expect_res[key]
            if e_res != item["result"]["info"]:
                self.log_info("%s sport hash %s result not expected, expect %s but %s" % (
                    op, key, e_res, item["result"]["info"]))
                return False
            if op == "add":
                if e_res == "success":
                    if key not in in_device_cfgs:
                        self.log_info("%s sport hash %s success, but not set in device" % (op, key))
                        return False
                    if in_device_cfgs[key] != item['vxlanSportHashRule']:
                        self.log_info("%s sport hash  %s success, but %s inconsitent with %s in device" %
                                      (op, key, str(item['vxlanSportHashRule']), str(in_device_cfgs[key])))
                        return False
            else:
                if e_res == "success":
                    if key in in_device_cfgs:
                        self.log_info("%s sport hash %s success, but still in device" % (op, key))
                        return False
        return True

    def _handle_vxlan_sport_hash_rule(self, vrfname, sport_hash_rules, op):
        """
        下发vni mtu配置
            item: eg: {"mac_type": 0x8809, "ip_proto": 0, "dst_port": 0, "hash_mode": "normal/ten_tuple/perpacket",  "expect_res": "success"}
        """
        if len(sport_hash_rules) == 0:
            return
        dict_request = {
            "vrf": {
                "vrfName": vrfname
            },
            "vxlanSportHashRules": [
            ]
        }

        expect_res = {}
        for index in range(len(sport_hash_rules)):
            sport_hash_rule = sport_hash_rules[index]
            item = {}
            item["mac_type"] = sport_hash_rule['mac_type']
            item["ip_proto"] = sport_hash_rule['ip_proto']
            item["dst_port"] = sport_hash_rule['dst_port']
            if sport_hash_rule['hash_mode'] == "normal":
                item["hash_mode"] = 0
            elif sport_hash_rule['hash_mode'] == "ten_tuple":
                item["hash_mode"] = 1
            else:
                item["hash_mode"] = 2
            dict_request["vxlanSportHashRules"].append(item)
            key = "%d_%d_%d" % (item["mac_type"], item["ip_proto"], item["dst_port"])
            if "expect_res" in sport_hash_rule:
                expect_res[key] = sport_hash_rule["expect_res"]
            else:
                expect_res[key] = "success"
            if (index + 1) % 20000 == 0:
                grpc_ret = None
                if op == "add":
                    grpc_ret = self.ntb_grpc_client.grpc_call("addVxlanSportHashRule", dict_request)
                else:
                    grpc_ret = self.ntb_grpc_client.grpc_call("delVxlanSportHashRule", dict_request)

                self.assert_("%s sport hash rule faild, not expected" % (op),
                             self._check_vxlan_sport_hash_rule_res(vrfname, op, grpc_ret["vxlanSportHashCfgResults"], expect_res))
                expect_res = {}
                dict_request["vxlanSportHashRules"].clear()
        if len(dict_request["vxlanSportHashRules"]) > 0:
            grpc_ret = None
            if op == "add":
                grpc_ret = self.ntb_grpc_client.grpc_call("addVxlanSportHashRule", dict_request)
            else:
                grpc_ret = self.ntb_grpc_client.grpc_call("delVxlanSportHashRule", dict_request)
            self.assert_("%s sport hash rule faild, not expected" % (op),
                            self._check_vxlan_sport_hash_rule_res(vrfname, op, grpc_ret["vxlanSportHashCfgResults"], expect_res))

    def add_vxlan_sport_port_hash_rule(self, vrfname, sport_hash_rules):
        """
        创建vxlan sport hash rule
        :param vrfname: vrf name
        :param sport_hash_rules: rules列表
            item: eg: {"mac_type": 0x8809, "ip_proto": 0, "dst_port": 0, "hash_mode": "normal/ten_tuple/perpacket",  "expect_res": "success"}
        :return
        """
        self._handle_vxlan_sport_hash_rule(vrfname, sport_hash_rules, "add")

    def del_vxlan_sport_port_hash_rule(self, vrfname, sport_hash_rules):
        """
        删除vxlan sport hash rule
        :param vrfname: vrf name
        :param sport_hash_rules: rules列表
            item: eg: {"mac_type": 0x8809, "ip_proto": 0, "dst_port": 0, "hash_mode": "normal/ten_tuple/perpacket",  "expect_res": "success"}
        :return
        """
        self._handle_vxlan_sport_hash_rule(vrfname, sport_hash_rules, "del")

    def _handle_nfc_vrf(self, vrfname, op):
        """
        下发nfc vrf config
        """
        if len(vrfname) == 0:
            return
    
        VrfRequest_dict = { 
            'vrf': { 'vrfName' : vrfname } 
        }

        grpc_ret = None
        if op == "create":
            grpc_ret = self.nfc_grpc_client.grpc_call("createVrf", VrfRequest_dict)
        else:
            grpc_ret = self.nfc_grpc_client.grpc_call("deleteVrf", VrfRequest_dict)
        self.assert_("%s nfc vrf faild, not expected" % (op), grpc_ret["info"] == "ok")

    def nfc_create_vrf(self, vrfname):
        """
        创建 nfc vrf
        """
        self._handle_nfc_vrf(vrfname, "create")

    def nfc_delete_vrf(self, vrfname):
        """
        删除 nfc vrf
        """
        self._handle_nfc_vrf(vrfname, "delete")
    
    def nfc_get_vrf(self, vrfname):
        """
        获取vrf信息
        """
        vrf_info = {}
        VrfRequest_dict = { 
            'vrf': { 'vrfName' : vrfname } 
        }
        grpc_ret = self.nfc_grpc_client.grpc_call("getVrfDetail", VrfRequest_dict)
        self.assert_("get nfc vrf faild, not expected", grpc_ret["result"]["info"] == "ok")
        vrf_info["vrfname"] = vrfname
        vrf_info["curFlowNum"] = grpc_ret["stat"]["curFlowNum"]
        vrf_info["totalFlowNum"] = grpc_ret["stat"]["totalFlowNum"]
        vrf_info["totalReportNum"] = grpc_ret["stat"]["totalReportNum"]
        vrf_info["totalTimeoutNum"] = grpc_ret["stat"]["totalTimeoutNum"]
        vrf_info["totalEliminateNum"] = grpc_ret["stat"]["totalEliminateNum"]
        return vrf_info

    def _handle_nfc_bind_vrf_service_info(self, vrfname, servicetype, serviceid, op):
        """
        下发nfc vrf config
        """
        if len(vrfname) == 0:
            return
        
        VrfServiceInfoReq_dict = {
            'vrf': { 'vrfName' : vrfname },
            "serviceType": servicetype,
            "serviceId": serviceid,
            "vpcId": "0",
            "instanceId": "0",
            "action": 1,
            "owner": "0",
            "uin": "0",
            "storageType": 1,
            "sflowInstanceId": "0",
            "ckafkaInstance": "0",
            "ckafkaTopic": "0",
            "ckafkaEndPoint": "0"
        }

        grpc_ret = None
        if op == "bind":
            grpc_ret = self.nfc_grpc_client.grpc_call("bindVrfServiceInfo", VrfServiceInfoReq_dict)
        else:
            grpc_ret = self.nfc_grpc_client.grpc_call("unbindVrfServiceInfo", VrfServiceInfoReq_dict)
        self.assert_("%s nfc vrf bind service faild, not expected" % (op), grpc_ret["info"] == "ok")

    def nfc_bind_vrf_service_info(self, vrfname, servicetype, serviceid):
        """
        绑定 nfc vrf service
        """
        self._handle_nfc_bind_vrf_service_info(vrfname, servicetype, serviceid, "bind")

    def nfc_unbind_vrf_service_info(self, vrfname, servicetype, serviceid):
        """
        解绑 nfc vrf service
        """
        self._handle_nfc_bind_vrf_service_info(vrfname, servicetype, serviceid, "unbind")

    def _parse_ipaddr_dict_2_ipaddress(self, ipaddr):
        """
        解析grpc ipaddr对象
        :param ipaddr: ip地址 grpc对象
        :return family, ip
        """
        family = ipaddr["family"]
        if family == 2:
            return ipaddress.ip_address(ipaddr["ip6Addr"])
        else:
            return ipaddress.ip_address(ipaddr["ipAddr"])
 
    def _parse_ipaddr_dict_2_ipaddress(self, ipaddr):
        """
        解析grpc ipaddr对象
        :param ipaddr: ip地址 grpc对象
        :return family, ip
        """
        family = ipaddr["family"]
        if family == 2:
            return ipaddress.ip_address(ipaddr["ip6Addr"])
        else:
            return ipaddress.ip_address(ipaddr["ipAddr"])

    def tuples_to_string(self, sip, dip, proto, sport, dport):
        strsip=ipaddress.ip_address(str(sip))
        strdip=ipaddress.ip_address(str(dip))
        return "sip:{} dip:{} proto:{} sprot:{} dport:{}".format(strsip, strdip, proto, sport, dport)      
    def _process_tuples_result(self, tupleinfos=[]):      
        ret_map = {}
        for tupleinfo in tupleinfos:
            sip = self._parse_ipaddr_dict_2_ipaddress(tupleinfo['src']['ipAddr'])
            dip = self._parse_ipaddr_dict_2_ipaddress(tupleinfo['dst']['ipAddr'])
            sport = 0
            dport = 0
            protocol = tupleinfo['l4Proto']
            rbytes = tupleinfo['bytes']
            rpkts  = tupleinfo['pkts']
            if protocol == socket.IPPROTO_TCP or protocol == socket.IPPROTO_UDP:
                sport = tupleinfo['srcPort']
                dport = tupleinfo['dstPort']
            map_key = self.tuples_to_string(sip, dip, protocol, sport, dport)
            ret_map[map_key] = (rpkts, rbytes)
        return ret_map

    def nfc_get_vrf_match(self, table=None, vrf=None, src=None, dst=None, proto=None, sport=None, dport=None, dscp=None):
        request = {}
        if vrf != None:
            request['vrf'] = {'val': vrf}
        if src != None:
            request['src'] = {'val': src}
        if dst != None:
            request['dst'] = {'val': dst}
        if proto != None:
            request['proto'] = {'val': proto}
        if sport != None:
            request['sport'] = {'val': sport}
        if dport != None:
            request['dport'] = {'val': dport}
        if dscp != None:
            request['dscp'] = {'val': dscp}

        ret_maps = {}
        if table is None:
            table = 0
            while True:
                request["table"] = table
                grpc_ret = self.nfc_grpc_client.grpc_call("getFlowTableMatch", request)
                if grpc_ret["result"]["info"] != "ok":
                    return ret_maps
                else:
                    table = table + 1
                    tmpmap = self._process_tuples_result(grpc_ret['tuples'])
                    ret_maps.update(tmpmap)
        else:
            request["table"] = table
            # request = {"table": table}
            grpc_ret = grpc_client.grpc_call("getFlowTableMatch", request)
            self.assert_("%s nfc getFlowTableMatch faild, not expected" % (op), grpc_ret["result"]["info"] == "ok")
            tmpmap = self._process_tuples_result(grpc_ret['tuples'])
            return tmpmap
    
    def _handle_check_qos_meter(self, op, qos_list, grpc_ret, expect_res):
        """ qos meter配置检查 """
        rets = grpc_ret["qosMeterResults"]
        items = {}
        for meter_rets in rets:
            name = meter_rets["meter"]["name"]
            cir = meter_rets["meter"]["cir"]
            cbs = meter_rets["meter"]["cbs"]
            res = meter_rets["result"]["info"]
            items[name] = {"name": name, "cir": cir, "cbs": cbs, "res": res}

        for qos in qos_list:
            e_res = expect_res[qos["name"]]
            if e_res != items[qos['name']]['res']:
                self.log_info("%s qos meter %s result not expected, expect %s but %s" % (
                    op, qos['name'], e_res, items[qos['name']]['res']))
                return False
            if e_res == 'success':
                if int(qos["cir"]) != int(items[qos["name"]]["cir"]) or \
                        int(qos["cbs"]) != int(items[qos["name"]]["cbs"]):
                    return False
        return True

    def _handle_qos_meter(self, qos_list, op, check=True):
        """ 下发qos meter配置 """
        if len(qos_list) == 0:
            return
        qos_meter_request = { 
            "meters" : [] 
        }

        items = []
        expect_res = {}
        for qos in qos_list:
            items.append({"name" : qos["name"], "cir" : qos["cir"], "cbs" : qos["cbs"]})
            if "expect_res" not in qos:
                qos["expect_res"] =  "success"
            expect_res[qos["name"]] = qos["expect_res"]
        qos_meter_request["meters"] = items

        grpc_ret = None
        if op == "create":
            grpc_ret = self.ntb_grpc_client.grpc_call("addQosMeter", qos_meter_request)
        else:
            grpc_ret = self.ntb_grpc_client.grpc_call("delQosMeter", qos_meter_request)

        if check:
            self.assert_("%s qos meter faild, not expected" % (op), self._handle_check_qos_meter(op, items, grpc_ret, expect_res))
        else:
            self.assert_("%s qos meter faild, not expected" % (op), grpc_ret["result"]["info"] == "success")

    def create_qos_meter(self, qos_list, check=True):
        """
        创建qos meter
        :param name: meter name
        :param cir : cir(Kbits)
        :param cbs : cbs(Kbits)
            item: eg: {[{"name":'qos_meter_test', "cir":100, "cbs":100}], "action":"accept", "expect_res": "success"}
        :return
        """
        self._handle_qos_meter(qos_list, "create", check)

    def delete_qos_meter(self, qos_list, check=True):
        """
        删除qos meter
        :param name: meter name
        :param cir : cir(Kbits)
        :param cbs : cbs(Kbits)
            item: eg: {[{"name":'qos_meter_test', "cir":100, "cbs":100}], "action":"accept", "expect_res": "success"}
        :return
        """
        self._handle_qos_meter(qos_list, "delete", check)

    def _handle_check_tun_meter(self, tun_meter_map_list, grpc_ret):
        """ tunnel meter映射关系配置检查 """
        rets = grpc_ret["tunQosMeterResults"]
        items = {}
        for tun_meter_rets in rets:
            tunQosMeter = tun_meter_rets["tunQosMeter"]
            vni = tunQosMeter["vni"]
            qos = tunQosMeter["qos"]
            items[vni] = {"vni": vni, "qos": qos}
        for tun_meter in tun_meter_map_list:
            if tun_meter["vni"] not in items.keys():
                return False
            else:
                if tun_meter["qos"] != items[tun_meter["vni"]]["qos"]:
                    return False
        return True

    def _handle_tunnel_qos(self, tun_meter_map_list, op, check=True):
        """ 下发qos meter配置 """
        if len(tun_meter_map_list) == 0:
            return
        tun_qos_meter_request = { 
            "tunQosMeters" : [] 
        }

        items = []
        for tun_meter_map in tun_meter_map_list:
            items.append({"vni" : tun_meter_map["vni"], "qos" : tun_meter_map["qos"]})
        tun_qos_meter_request["tunQosMeters"] = items

        grpc_ret = None
        if op == "bind":
            grpc_ret = self.ntb_grpc_client.grpc_call("bindTunnelToQosMeter", tun_qos_meter_request)
        else:
            grpc_ret = self.ntb_grpc_client.grpc_call("unbindTunnelToQosMeter", tun_qos_meter_request)

        if check:
            self.assert_("%s tunnel to meter faild, not expected" % (op), self._handle_check_tun_meter(items, grpc_ret))
        else:
            self.assert_("%s tunnel to meter faild, not expected" % (op), grpc_ret["result"]["info"] == "success")

    def bind_tunnel_to_qos_meter(self, tun_meter_map_list, check=True):
        """
        添加meter和tunnel的映射
        :param vni: vni
        :param qos : qos meter name
            item: eg: {[{"vni": 1000, "qos": "qos_meter_test"}], "action":"accept"}
        :return
        """
        self._handle_tunnel_qos(tun_meter_map_list, "bind", check)

    def unbind_tunnel_to_qos_meter(self, tun_meter_map_list, check=True):
        """
        删除meter和tunnel的映射
        :param vni: vni
        :param qos : qos meter name
            item: eg: {[{"vni": 1000, "qos": "qos_meter_test"}], "action":"accept"}
        :return
        """
        self._handle_tunnel_qos(tun_meter_map_list, "unbind", check)

    def _handle_qos_meter_stats(self, qos_list, op, check=True):
        """ 获取/清除 qos meter统计 """
        if len(qos_list) == 0:
            return
        qos_meter_stats_request = { 
            "meters" : [] 
        }

        items = []
        for qos in qos_list:
            items.append({"name" : qos["name"], "cir": 0, "cbs": 0})
        qos_meter_stats_request["meters"] = items

        grpc_ret = None
        if op == "get":
            grpc_ret = self.ntb_grpc_client.grpc_call("getQosMeterStats", qos_meter_stats_request)
        else:
            grpc_ret = self.ntb_grpc_client.grpc_call("clrQosMeterStats", qos_meter_stats_request)

        self.assert_("%s qos meter stats faild, not expected" % (op), grpc_ret["result"]["info"] == "success")

        if op == "get":
            items = grpc_ret["qosMeterStats"]
            return items
        else:
            return

    def clr_qos_meter_stats(self, qos_list, check=True):
        """
        清除qos meter的统计
        :param qos: qos meter name
            item: eg: {[{"name": "qos_meter_test"}], "action":"accept"}
        :return
        """
        return self._handle_qos_meter_stats(qos_list, "clear", check)

    def get_qos_meter_stats(self, qos_list, check=True):
        """
        获取qos meter的统计
        :param qos: qos meter name
            item: eg: {[{"name": "qos_meter_test"}], "action":"accept"}
        :return
        """
        return self._handle_qos_meter_stats(qos_list, "get", check)

    def construct_table_stress_test_env(self, vrf_num=1200, tunnel_num=6000, host_num=500000, lpm_num=85000, nhop_num=150000, ecmp_grp_num=2000, mroute_grp_num = 20000, neigh_num=8000):
        """
        # default
        # tunnel: 90000 ~ 90000+vrf_num
        # distributed in each vrf
        # tunnel:
        #   vrf1: 90000, 90000+vrf_num, ...
        #   vrf2: 90001, 90000+vrf_num+1, ...
        #   ...

        # cross vrf
        #   61.1.1.0/24
        
        # host
        #   11.1.1.1-11.1.2.160

        # ecmp
        #   21.1.1.0/24
        #   21::/64

        # mroute
        #   31.1.1.0/24-31.1.12.0/24
        #   31::/64-31:0:0:3::/64

        # neigh
        #   41.1.1.0/24-41.1.4.0/24
        #   41::/64

        # lpm
        #   61.1.1.0/24-61.1.53.24
        #   61::/64-61:0:0:f::/64
        """

        self.spirent_port_ip = settings.SPIRENT_PORT_IP
        self.spirent_port_peer_ip = settings.SPIRENT_PORT_PEER_IP

        nhop_ip_list = []
        nhop_ip_list.append(self.spirent_port_ip)
        nhop = ip_to_int("13.13.13.1")
        for i in range(0, 50):
            nhop_ip_list.append(int_to_ip(nhop+i))

        # 创建2K vrf
        stress_cfg = {}
        for i in range(0, vrf_num):
            vrf_name = "table_stress_test_%s" % i
            stress_cfg[vrf_name] = {}
            self.create_vrf(vrf_name)
            # self.delete_vrf(vrf_name)
        # return
        tunnel_num_per_vrf = tunnel_num // vrf_num
        tunnel_remain_num = tunnel_num % vrf_num

        # 创建tunnel, bundle
        vni = 90000
        ovni = tunnel_num+vni
        vrf_list = list(stress_cfg)
        for i in range(0, tunnel_num_per_vrf):
            for vrf in vrf_list:
                if "tunnel" not in stress_cfg[vrf]:
                    stress_cfg[vrf]["tunnel"] = []
                    stress_cfg[vrf]["bundle"] = []
                stress_cfg[vrf]["tunnel"].append({"vni": vni})
                stress_cfg[vrf]["bundle"].append({"ivni": vni, "ovni": ovni})
                vni = vni + 1
                ovni = ovni + 1

        for i in range(0, tunnel_remain_num):
            if "tunnel" not in stress_cfg[vrf_list[i]]:
                stress_cfg[vrf_list[i]]["tunnel"] = []
                stress_cfg[vrf_list[i]]["bundle"] = []
            stress_cfg[vrf_list[i]]["tunnel"].append({"vni": vni})
            stress_cfg[vrf_list[i]]["bundle"].append({"ivni": vni, "ovni": ovni})
            vni = vni + 1
            ovni = ovni + 1

        for vrf in stress_cfg:
            tunnel_list = []
            bundle_list = []
            if "tunnel" in stress_cfg[vrf]:
                tunnel_list = stress_cfg[vrf]["tunnel"]
                bundle_list = stress_cfg[vrf]["bundle"]
            self.create_vxlan_tunnel(vrf, tunnel_list, check=False)
            self.create_vxlan_tunnel_bundle(vrf, bundle_list, check=False)

        pfx = ip_to_int("61.1.1.1")
        pfx6 = get_ipv6_prefix("61::1", count=1)
        vni = 90000
        for i in range(0, 1):
            for vrf_idx in range(0, len(vrf_list)//2):
                if "cross" not in stress_cfg[vrf_list[vrf_idx]]:
                    stress_cfg[vrf_list[vrf_idx]]["cross"] = []
                stress_cfg[vrf_list[vrf_idx]]["cross"].append({"prefix": int_to_ip(pfx),
                                                "plen": 24,
                                                "nexthop": settings.NTB_FWD_VIP,
                                                "vni":(vni+vrf_idx+len(vrf_list)//2)+i*len(vrf_list)})
                stress_cfg[vrf_list[vrf_idx]]["cross"].append({"prefix": pfx6[0],
                                                "plen": 64,
                                                "nexthop": settings.NTB_FWD_VIP,
                                                "vni":(vni+vrf_idx+len(vrf_list)//2)+i*len(vrf_list)})
        for vrf in stress_cfg:
            cross_list = []
            if "cross" in stress_cfg[vrf]:
                cross_list = stress_cfg[vrf]["cross"]
            self.create_vxlan_route(vrf, cross_list, check=False)

        # 创建host路由
        host_num_per_vrf = host_num // vrf_num
        # host_remain_num = host_num % vrf_num
        pfx = ip_to_int("11.1.1.1")
        vrf_list = list(stress_cfg)
        for vrf in vrf_list:
            # if i < host_remain_num:
            #     host_num_per_vrf = host_num_per_vrf + 1
            for _ in range(0, host_num_per_vrf):
                if "host" not in stress_cfg[vrf]:
                    stress_cfg[vrf]["host"] = []
                stress_cfg[vrf]["host"].append({"prefix": int_to_ip(pfx), 
                                                "plen": 32,
                                                "nexthop": nhop_ip_list[random.randint(0, len(nhop_ip_list)-1)],
                                                "vpcid":20001})
                pfx = pfx + 1
            pfx = ip_to_int("11.1.1.1")

        for vrf in stress_cfg:
            host_list = []
            if "host" in stress_cfg[vrf]:
                host_list = stress_cfg[vrf]["host"]
            self.create_gre_route(vrf, host_list, check=False)
        self.get_hw_spec()

        vrf_list = list(stress_cfg)
        # 创建ecmp
        ecmp_num_per_vrf = ecmp_grp_num // vrf_num
        # ecmp_remain_num = ecmp_grp_num % vrf_num
        # ecmp_mbr = 2
        ecmp_pfx = ip_to_int("21.1.1.0")
        ecmp_pfx6 = get_ipv6_prefix(prefix_start='21::1', count=ecmp_grp_num)
        # cross_pfx = ip_to_int("71.1.1.0")
        vni = 20001
        for vrf in vrf_list:
            for i in range(0, ecmp_num_per_vrf):
                if "ecmp" not in stress_cfg[vrf]:
                    stress_cfg[vrf]["ecmp"] = []
                # if "cross1" not in stress_cfg[vrf]:
                #     stress_cfg[vrf]["cross1"] = []
                for _ in range(0, 1):
                    nhop = ip_to_int("13.13.13.1")
                    stress_cfg[vrf]["ecmp"].append({"prefix": int_to_ip(ecmp_pfx), 
                                                    "plen": 24,
                                                    "nexthop": self.spirent_port_ip,
                                                    "vni":vni})

                    stress_cfg[vrf]["ecmp"].append({"prefix": ecmp_pfx6[i], 
                                                    "plen": 64,
                                                    "nexthop": self.spirent_port_ip,
                                                    "vni":vni})

                    for _ in range(0, 50):
                        stress_cfg[vrf]["ecmp"].append({"prefix": int_to_ip(ecmp_pfx), 
                                                        "plen": 24,
                                                        "nexthop": int_to_ip(nhop),
                                                        "vni":vni})
                        stress_cfg[vrf]["ecmp"].append({"prefix": ecmp_pfx6[i], 
                                                        "plen": 64,
                                                        "nexthop": int_to_ip(nhop),
                                                        "vni":vni})
                        nhop = nhop + 1
                    vni = vni + 1
                ecmp_pfx = ecmp_pfx + 256
            ecmp_pfx = ip_to_int("21.1.1.0")

        for vrf in stress_cfg:
            ecmp_list = []
            cross_list = []
            if "ecmp" in stress_cfg[vrf]:
                ecmp_list = stress_cfg[vrf]["ecmp"]
            if "cross1" in stress_cfg[vrf]:
                cross_list = stress_cfg[vrf]["cross1"]
            self.create_vxlan_route(vrf, ecmp_list, check=False)
            self.create_vxlan_route(vrf, cross_list, check=False)
        self.get_hw_spec()

        # 创建mroute
        vrf_list = list(stress_cfg)
        mroute_num_per_vrf = mroute_grp_num // vrf_num //5*4
        # mroute_remain_num = mroute_grp_num % vrf_num
        mroute_mbr = 2
        mroute_pfx = ip_to_int("31.1.1.0")
        mroute_pfx6 = get_ipv6_prefix("31::1", count=mroute_num_per_vrf)
        # cross_pfx = ip_to_int("81.1.1.0")
        # nhop = ip_to_int("13.13.13.1")
        for vrf in vrf_list:
            for i in range(0, mroute_num_per_vrf):
                vni = 20001
                # nhop = ip_to_int("13.13.13.1")
                if "mroute" not in stress_cfg[vrf]:
                    stress_cfg[vrf]["mroute"] = []
                # if "cross2" not in stress_cfg[vrf]:
                #     stress_cfg[vrf]["cross2"] = []

                for _ in range(0, mroute_mbr):
                    stress_cfg[vrf]["mroute"].append({"prefix": int_to_ip(mroute_pfx), 
                                                    "plen": 24,
                                                    "nexthop": self.spirent_port_ip,
                                                    "vni":vni})
                    if i < mroute_num_per_vrf//4:
                        stress_cfg[vrf]["mroute"].append({"prefix": mroute_pfx6[i], 
                                "plen": 64,
                                "nexthop": self.spirent_port_ip,
                                "vni":vni})

                    vni = vni + 1
                mroute_pfx = mroute_pfx + 256
            mroute_pfx = ip_to_int("31.1.1.0")

        for vrf in stress_cfg:
            mroute_list = []
            cross_list = []
            if "mroute" in stress_cfg[vrf]:
                mroute_list = stress_cfg[vrf]["mroute"]
            self.create_mroute(vrf, mroute_list, check=False)
        self.get_hw_spec()

        # 创建sflow
        cur_cnt, max_cnt = self.get_hw_spec("NTB_SFLOW_OBJ")
        sflow_list = []
        for vrf in vrf_list:
            if len(sflow_list) == max_cnt:
                break
            sflow_list.append({"vrf": vrf, "serviceType":1, "serviceId":1, "action":"accept"})
        self.create_sflow(sflow_list, check=False)

        # neigh_num = 9000
        neigh_num_per_vrf = neigh_num // vrf_num//5*4
        # neigh_remain_num = neigh_num % vrf_num
        pfx = ip_to_int("41.1.1.0")
        pfx6 = get_ipv6_prefix('41::1', count=neigh_num_per_vrf)
        gateway = ip_to_int("51.1.1.1")
        gateway6 = int(ipaddress.IPv6Address("51::1"))
        vrf_list = list(stress_cfg)
        vni = 20001
        # print("neigh lpm占用: %s, nhop占用: %s, neigh占用: %s" % (vrf_num*(neigh_num_per_vrf), vrf_num*(neigh_num_per_vrf),vrf_num*(neigh_num_per_vrf)))
        for vrf in vrf_list:
            for i in range(0, neigh_num_per_vrf):
                if "nhop_with_gateway" not in stress_cfg[vrf]:
                    stress_cfg[vrf]["nhop_with_gateway"] = []
                    stress_cfg[vrf]["neigh"] = []
                stress_cfg[vrf]["nhop_with_gateway"].append({"prefix": int_to_ip(pfx), 
                                                            "plen": 24,
                                                            "nexthop": nhop_ip_list[random.randint(0, len(nhop_ip_list)-1)],
                                                            "gateway": int_to_ip(gateway),
                                                            "vni":vni})
                if i < neigh_num_per_vrf//4:
                    # gateway6 = get_a_valid_random_ipv6()
                    stress_cfg[vrf]["nhop_with_gateway"].append({"prefix": pfx6[i], 
                                                                "plen": 64,
                                                                "nexthop": nhop_ip_list[random.randint(0, len(nhop_ip_list)-1)],
                                                                "gateway": str(ipaddress.IPv6Address(gateway6)),
                                                                "vni":vni})
                    stress_cfg[vrf]["neigh"].append({"ip": str(ipaddress.IPv6Address(gateway6)), "mac": "ac:de:48:00:11:22"})
                stress_cfg[vrf]["neigh"].append({"ip": int_to_ip(gateway), "mac": "ac:de:48:00:11:22"})
                gateway = gateway + 1
                gateway6 = gateway6 + 1
                pfx = pfx + 256
            pfx = ip_to_int("41.1.1.0")

        for vrf in stress_cfg:
            nhop_with_gateway_list = []
            neigh_list = []
            if "nhop_with_gateway" in stress_cfg[vrf]:
                nhop_with_gateway_list = stress_cfg[vrf]["nhop_with_gateway"]
                neigh_list = stress_cfg[vrf]["neigh"]
            self.create_vxlan_route(vrf, nhop_with_gateway_list, check=False)
            self.set_overlay_arp(vrf, neigh_list, False)
        self.get_hw_spec()

        # # 创建nexthop
        # cur_cnt, max_cnt = self.get_hw_spec("NTB_NHOP_OBJ")
        # nhop_num = nhop_num - cur_cnt
        # nhop_num_per_vrf = nhop_num // vrf_num
        # # nhop_remain_num = nhop_num % vrf_num
        # pfx = ip_to_int("91.1.1.0")
        # nhop = ip_to_int("13.13.13.1")
        # vni = 20001
        # # vrf_list = list(stress_cfg)
        # for vrf in vrf_list:
        #     for _ in range(0, nhop_num_per_vrf):
        #         if "nhop" not in stress_cfg[vrf]:
        #             stress_cfg[vrf]["nhop"] = []
        #         for _ in range(0, 13):
        #         stress_cfg[vrf]["nhop"].append({"prefix": int_to_ip(pfx), 
        #                                        "plen": 24,
        #                                        "nexthop": int_to_ip(nhop),
        #                                        "vni":vni})
        #         nhop = nhop + 1
        #         pfx = pfx + 256

        # for vrf in stress_cfg:
        #     nhop_list = []
        #     if "nhop" in stress_cfg[vrf]:
        #         nhop_list = stress_cfg[vrf]["nhop"]
        #     self.create_vxlan_route(vrf, nhop_list)

        # 创建cross vrf



        # # 创建lpm
        # cur_cnt, max_cnt = self.get_hw_spec("NTB_NHOP_OBJ")
        # nhop_num = nhop_num - cur_cnt
        # nhop_num_per_vrf = nhop_num // vrf_num
        cur_cnt, max_cnt = self.get_hw_spec("NTB_EGRESS_TUNNEL_OBJ")
        eg_tun_num = max_cnt - cur_cnt
        eg_tun_num_per_vrf = eg_tun_num // vrf_num

        cur_cnt, max_cnt = self.get_hw_spec("NTB_FIB_LPM_OBJ")
        lpm_num = lpm_num - cur_cnt
        # if eg_tun_num_per_vrf != 0:
        #     lpm_num_per_vrf = lpm_num // vrf_num // eg_tun_num_per_vrf
        # else:
        lpm_num_per_vrf = lpm_num // vrf_num
        print(lpm_num_per_vrf)
        pfx = ip_to_int("61.1.1.0")
        nhop = ip_to_int("13.13.13.1")
        vrf_list = list(stress_cfg)
        vni = 30001
        for vrf in vrf_list:
            for i in range(0, lpm_num_per_vrf):
                if "lpm" not in stress_cfg[vrf]:
                    stress_cfg[vrf]["lpm"] = []
                for _ in range(0, 50):
                    stress_cfg[vrf]["lpm"].append({"prefix": int_to_ip(pfx), 
                                                "plen": 24,
                                                "nexthop": int_to_ip(nhop),
                                                "vni":vni})
                    if i != 0:
                        break
                    nhop = nhop + 1
                pfx = pfx + 256
                nhop = ip_to_int("13.13.13.1")
            vni = vni + 1
            pfx = ip_to_int("61.1.1.0")

        for vrf in stress_cfg:
            lpm_list = []
            if "lpm" in stress_cfg[vrf]:
                lpm_list = stress_cfg[vrf]["lpm"]
            self.create_vxlan_route(vrf, lpm_list, check=False)

        cur_cnt, max_cnt = self.get_hw_spec("NTB_FIB_LPM6_OBJ")
        lpm_num = 32000
        lpm_num = lpm_num - cur_cnt
        # if eg_tun_num_per_vrf != 0:
        #     lpm_num_per_vrf = lpm_num // vrf_num // eg_tun_num_per_vrf
        # else:
        lpm_num_per_vrf = lpm_num // vrf_num
        print(lpm_num_per_vrf)
        pfx6 = get_ipv6_prefix("61::1", count=lpm_num_per_vrf)
        nhop = ip_to_int("13.13.13.1")
        vrf_list = list(stress_cfg)
        vni = 30001
        for vrf in vrf_list:
            for i in range(0, lpm_num_per_vrf):
                if "lpm6" not in stress_cfg[vrf]:
                    stress_cfg[vrf]["lpm6"] = []
                for _ in range(0, 50):
                    stress_cfg[vrf]["lpm6"].append({"prefix": pfx6[i], 
                                                "plen": 64,
                                                "nexthop": int_to_ip(nhop),
                                                "vni":vni})
                    if i != 0:
                        break
                    nhop = nhop + 1
                nhop = ip_to_int("13.13.13.1")
            vni = vni + 1

        for vrf in stress_cfg:
            lpm_list = []
            if "lpm6" in stress_cfg[vrf]:
                lpm_list = stress_cfg[vrf]["lpm6"]
            self.create_vxlan_route(vrf, lpm_list, check=False)

    def ipv6_address_construct(self, index, base="2004"):
        prefix_base = "{}::{:X}:{:X}".format(base, int(index/256), int(index%256))
        ip_v6 = ipaddress.ip_address(prefix_base)
        ip_v6_str = ip_v6.compressed
        return ip_v6_str

    def batch_vrf_config(self, vrf_list, op, check=True):
        request = ntb_config_pb2.DeviceConfigRequest()
        for vrf in vrf_list:
            req = ntb_config_pb2.VrfRequest()
            tmp = {
                "vrf": self._parse_vrf(vrf)
            }
            request.data.append(self.dict_to_grpc_any(tmp, req))
        request.type = ntb_config_pb2.BatchConfigType.BATCH_VRF
        request.opt = ntb_config_pb2.Operation.ADD  if op == "create" else ntb_config_pb2.Operation.DELETE

        stub = ntb_config_pb2_grpc.NtbServiceStub(self.ntb_grpc_client.channel)
        start = time.time()
        grpc_ret = stub.batchDeviceConfig(request=request, metadata=self.ntb_grpc_client.metadata)
        end = time.time()
        print("batch vrf config cost {}s".format(end-start))

        # print(grpc_ret)

    def batch_vrf_ip_config(self, vrf_list, op, check=True):
        request = ntb_config_pb2.DeviceConfigRequest()
        for vrf in vrf_list:
            req = ntb_config_pb2.VrfIpRequest()
            tmp = {
                "vrf": self._parse_vrf(vrf['vrf']),
                "rtIpInfoes":[]
            }
            tmp["rtIpInfoes"].append({
                "ip": self._encap_prefix_item(vrf['ip'], 32, "ipv4"),
                "type": 2
            })
            request.data.append(self.dict_to_grpc_any(tmp, req))
        request.type = ntb_config_pb2.BatchConfigType.BATCH_VRF_IP
        request.opt = ntb_config_pb2.Operation.ADD  if op == "create" else ntb_config_pb2.Operation.DELETE

        stub = ntb_config_pb2_grpc.NtbServiceStub(self.ntb_grpc_client.channel)
        start = time.time()
        grpc_ret = stub.batchDeviceConfig(request=request, metadata=self.ntb_grpc_client.metadata)
        end = time.time()
        print("batch vrf ip config cost {}s".format(end-start))

        # print(grpc_ret)

    def batch_tunnel_vxlan_config(self, vrf_list, op, check=True):
        request = ntb_config_pb2.DeviceConfigRequest()
        for vrf in vrf_list:
            req = ntb_config_pb2.TunnelVxlanRequest()
            tmp = {
                "vrf": self._parse_vrf(vrf['vrf']),
                "tunnelVxlans":[]
            }
            tmp["tunnelVxlans"].append({
                "vxlanVni": vrf['vni'],
            })
            request.data.append(self.dict_to_grpc_any(tmp, req))
        request.type = ntb_config_pb2.BatchConfigType.BATCH_TUNNEL_VXLAN
        request.opt = ntb_config_pb2.Operation.ADD  if op == "create" else ntb_config_pb2.Operation.DELETE

        stub = ntb_config_pb2_grpc.NtbServiceStub(self.ntb_grpc_client.channel)
        start = time.time()
        grpc_ret = stub.batchDeviceConfig(request=request, metadata=self.ntb_grpc_client.metadata)
        end = time.time()
        print("batch tunnel vxlan config cost {}s".format(end-start))

        # print(grpc_ret)

    def batch_tunnel_gre_config(self, vrf_list, op, check=True):
        request = ntb_config_pb2.DeviceConfigRequest()
        for vrf in vrf_list:
            req = ntb_config_pb2.TunnelGreRequest()
            tmp = {
                "vrf": self._parse_vrf(vrf['vrf']),
                "tunnelGres":[]
            }
            tmp["tunnelGres"].append({
                "greVpcId": vrf['vpcid'],
            })
            request.data.append(self.dict_to_grpc_any(tmp, req))
        request.type = ntb_config_pb2.BatchConfigType.BATCH_TUNNEL_GRE
        request.opt = ntb_config_pb2.Operation.ADD  if op == "create" else ntb_config_pb2.Operation.DELETE

        stub = ntb_config_pb2_grpc.NtbServiceStub(self.ntb_grpc_client.channel)
        start = time.time()
        grpc_ret = stub.batchDeviceConfig(request=request, metadata=self.ntb_grpc_client.metadata)
        end = time.time()
        print("batch tunnel gre config cost {}s".format(end-start))

        # print(grpc_ret)

    def batch_tunnel_bundle_config(self, vrf_list, op, check=True):
        request = ntb_config_pb2.DeviceConfigRequest()
        for vrf in vrf_list:
            req = ntb_config_pb2.TunnelBundleVxlanReq()
            tmp = {
                "vrf": self._parse_vrf(vrf['vrf']),
                "tunnelBundles":[]
            }
            tmp["tunnelBundles"].append({
                "vxlanVni_i": vrf['ivni'],
                "vxlanVni_o": vrf['ovni'],
            })
            request.data.append(self.dict_to_grpc_any(tmp, req))
        request.type = ntb_config_pb2.BatchConfigType.BATCH_TUNNEL_BUNDLE_VXLAN
        request.opt = ntb_config_pb2.Operation.ADD  if op == "create" else ntb_config_pb2.Operation.DELETE

        stub = ntb_config_pb2_grpc.NtbServiceStub(self.ntb_grpc_client.channel)
        start = time.time()
        grpc_ret = stub.batchDeviceConfig(request=request, metadata=self.ntb_grpc_client.metadata)
        end = time.time()
        print("batch tunnel bundle vxlan config cost {}s".format(end-start))

        # print(grpc_ret)

    def batch_agent_ip_config(self, vrf_list, op, check=True):
        request = ntb_config_pb2.DeviceConfigRequest()
        for vrf in vrf_list:
            req = ntb_config_pb2.AgentArpIpRequest()
            tmp = {
                "vrf": self._parse_vrf(vrf['vrf']),
                "agentArpIps":[]
            }
            tmp["agentArpIps"].append({
                "ip": self._encap_ip_item(vrf['ip'])
            })
            request.data.append(self.dict_to_grpc_any(tmp, req))
        request.type = ntb_config_pb2.BatchConfigType.BATCH_AGENT_IP
        request.opt = ntb_config_pb2.Operation.ADD  if op == "create" else ntb_config_pb2.Operation.DELETE

        stub = ntb_config_pb2_grpc.NtbServiceStub(self.ntb_grpc_client.channel)
        start = time.time()
        grpc_ret = stub.batchDeviceConfig(request=request, metadata=self.ntb_grpc_client.metadata)
        end = time.time()
        print("batch agent ip config cost {}s".format(end-start))

        # print(grpc_ret)

    def batch_sflow_config(self, vrf_list, op, check=True):
        request = ntb_config_pb2.DeviceConfigRequest()
        for vrf in vrf_list:
            req = ntb_config_pb2.VrfSflowRequest()
            tmp = {
                "sflowInfos":[]
            }
            tmp["sflowInfos"].append({
                "vrf": self._parse_vrf(vrf['vrf']),
                "serviceType": vrf['service_type'],
                "serviceId": vrf['service_id'],
                "action": vrf['action'],
            })
            request.data.append(self.dict_to_grpc_any(tmp, req))
        request.type = ntb_config_pb2.BatchConfigType.BATCH_VRF_SFLOW
        request.opt = ntb_config_pb2.Operation.ADD  if op == "create" else ntb_config_pb2.Operation.DELETE

        stub = ntb_config_pb2_grpc.NtbServiceStub(self.ntb_grpc_client.channel)
        start = time.time()
        grpc_ret = stub.batchDeviceConfig(request=request, metadata=self.ntb_grpc_client.metadata)
        end = time.time()
        print("batch sflow config cost {}s".format(end-start))

        # print(grpc_ret)

    def batch_ip_table_config(self, vrf_list, op, check=True):
        request = ntb_config_pb2.DeviceConfigRequest()
        for vrf in vrf_list:
            req = ntb_config_pb2.CreateIpTableRequest() if op == "create" else ntb_config_pb2.DeleteIpTableRequest()
            tmp = {
                "vrf": self._parse_vrf(vrf['vrf']),
                "family": vrf['family'],
                "tableId": vrf['table_id'],
            }
            request.data.append(self.dict_to_grpc_any(tmp, req))
        request.type = ntb_config_pb2.BatchConfigType.BATCH_IP_TABLE
        request.opt = ntb_config_pb2.Operation.ADD  if op == "create" else ntb_config_pb2.Operation.DELETE

        stub = ntb_config_pb2_grpc.NtbServiceStub(self.ntb_grpc_client.channel)
        start = time.time()
        grpc_ret = stub.batchDeviceConfig(request=request, metadata=self.ntb_grpc_client.metadata)
        end = time.time()
        print("batch ip table config cost {}s".format(end-start))

        # print(grpc_ret)

    def batch_vxlan_route_config(self, vrf_list, op, check=True):
        request = ntb_config_pb2.DeviceConfigRequest()
        for vrf in vrf_list:
            req = ntb_config_pb2.RouteVxlanRequest()
            tmp = {
                "vrf": self._parse_vrf(vrf['vrf']),
                "rtVxlans": []
            }
            for i in vrf['route']:
                tmp["rtVxlans"].append({
                    "prefix": self._encap_prefix_item(i['prefix'].split("/")[0], i['prefix'].split("/")[1], "ipv4"),
                    "nexthopIp": self._encap_ip_item(i['nexthop']),
                    "vni": i['vni'],
                    "gateway": self._encap_ip_item(i['gateway'] if "gateway" in i else "0.0.0.0")
                })
            request.data.append(self.dict_to_grpc_any(tmp, req))
        request.type = ntb_config_pb2.BatchConfigType.BATCH_ROUTE_VXLAN
        request.opt = ntb_config_pb2.Operation.ADD  if op == "create" else ntb_config_pb2.Operation.DELETE

        stub = ntb_config_pb2_grpc.NtbServiceStub(self.ntb_grpc_client.channel)
        start = time.time()
        grpc_ret = stub.batchDeviceConfig(request=request, metadata=self.ntb_grpc_client.metadata)
        end = time.time()
        print("batch vxlan route config cost {}s".format(end-start))

        # print(grpc_ret)

    def batch_gre_route_config(self, vrf_list, op, check=True):
        request = ntb_config_pb2.DeviceConfigRequest()
        for vrf in vrf_list:
            req = ntb_config_pb2.RouteGreRequest()
            tmp = {
                "vrf": self._parse_vrf(vrf['vrf']),
                "rtGres": []
            }
            for i in vrf['route']:
                tmp["rtGres"].append({
                    "prefix": self._encap_prefix_item(i['prefix'].split("/")[0], i['prefix'].split("/")[1], "ipv4"),
                    "nexthopIp": self._encap_ip_item(i['nexthop']),
                    "vpcId": {"id": i['vpcId']},
                     "vmIp": self._encap_ip_item(i['vmIp'] if "vmIp" in i else "0.0.0.0")
                })
            request.data.append(self.dict_to_grpc_any(tmp, req))
        request.type = ntb_config_pb2.BatchConfigType.BATCH_ROUTE_GRE
        request.opt = ntb_config_pb2.Operation.ADD  if op == "create" else ntb_config_pb2.Operation.DELETE

        stub = ntb_config_pb2_grpc.NtbServiceStub(self.ntb_grpc_client.channel)
        start = time.time()
        grpc_ret = stub.batchDeviceConfig(request=request, metadata=self.ntb_grpc_client.metadata)
        end = time.time()
        print("batch vxlan gre config cost {}s".format(end-start))

        # print(grpc_ret)

    def batch_blackhole_config(self, vrf_list, op, check=True):
        request = ntb_config_pb2.DeviceConfigRequest()
        for vrf in vrf_list:
            req = ntb_config_pb2.BlackholeRouteRequest()
            tmp = {
                "vrf": self._parse_vrf(vrf['vrf']),
                "bhRoutes": []
            }
            tmp["bhRoutes"].append({
                "prefix": self._encap_prefix_item(vrf['prefix'].split("/")[0], vrf['prefix'].split("/")[1], "ipv4"),
            })
            request.data.append(self.dict_to_grpc_any(tmp, req))
        request.type = ntb_config_pb2.BatchConfigType.BATCH_ROUTE_BLACKHOLE
        request.opt = ntb_config_pb2.Operation.ADD  if op == "create" else ntb_config_pb2.Operation.DELETE

        stub = ntb_config_pb2_grpc.NtbServiceStub(self.ntb_grpc_client.channel)
        start = time.time()
        grpc_ret = stub.batchDeviceConfig(request=request, metadata=self.ntb_grpc_client.metadata)
        end = time.time()
        print("batch blackhole config cost {}s".format(end-start))
        # print(grpc_ret)

    def batch_vxlan_mroute_config(self, vrf_list, op, check=True):
        request = ntb_config_pb2.DeviceConfigRequest()
        for vrf in vrf_list:
            req = ntb_config_pb2.RouteVxlanRequest()
            tmp = {
                "vrf": self._parse_vrf(vrf['vrf']),
                "rtVxlans": []
            }
            for i in vrf['route']:
                tmp["rtVxlans"].append({
                    "prefix": self._encap_prefix_item(i['prefix'].split("/")[0], i['prefix'].split("/")[1], "ipv4"),
                    "nexthopIp": self._encap_ip_item(i['nexthop']),
                    "vni": i['vni'],
                    "gateway": self._encap_ip_item(i['gateway'] if "gateway" in i else "0.0.0.0")
                })
            request.data.append(self.dict_to_grpc_any(tmp, req))
        request.type = ntb_config_pb2.BatchConfigType.BATCH_MROUTE_VXLAN
        request.opt = ntb_config_pb2.Operation.ADD  if op == "create" else ntb_config_pb2.Operation.DELETE

        stub = ntb_config_pb2_grpc.NtbServiceStub(self.ntb_grpc_client.channel)
        start = time.time()
        grpc_ret = stub.batchDeviceConfig(request=request, metadata=self.ntb_grpc_client.metadata)
        end = time.time()
        print("batch vxlan mroute config cost {}s".format(end-start))

        # print(grpc_ret)

    def batch_route_interface_config(self, vrf_list, op, check=True):
        request = ntb_config_pb2.DeviceConfigRequest()
        for vrf in vrf_list:
            req = ntb_config_pb2.VrfRouteInterfaceReq()
            tmp = {
                "vrf": self._parse_vrf(vrf['vrf']),
                "rtInterfaceInfos": []
            }
            tmp["rtInterfaceInfos"].append({
                "prefix": self._encap_prefix_item(vrf['prefix'].split("/")[0], vrf['prefix'].split("/")[1], "ipv4"),
                "mtu": vrf['mtu'],
            })
            request.data.append(self.dict_to_grpc_any(tmp, req))
        request.type = ntb_config_pb2.BatchConfigType.BATCH_ROUTE_INTERFACE
        request.opt = ntb_config_pb2.Operation.ADD  if op == "create" else ntb_config_pb2.Operation.DELETE

        stub = ntb_config_pb2_grpc.NtbServiceStub(self.ntb_grpc_client.channel)
        start = time.time()
        grpc_ret = stub.batchDeviceConfig(request=request, metadata=self.ntb_grpc_client.metadata)
        end = time.time()
        print("batch route interface config cost {}s".format(end-start))

        # print(grpc_ret)

    def batch_vrf_mac_config(self, vrf_list, op, check=True):
        request = ntb_config_pb2.DeviceConfigRequest()
        for vrf in vrf_list:
            req = ntb_config_pb2.VrfRMacRequest()
            tmp = {
                "vrf": self._parse_vrf(vrf['vrf']),
                "routeMac": vrf['routeMac']
            }
            request.data.append(self.dict_to_grpc_any(tmp, req))
        request.type = ntb_config_pb2.BatchConfigType.BATCH_VRF_MAC
        request.opt = ntb_config_pb2.Operation.ADD  if op == "create" else ntb_config_pb2.Operation.DELETE

        stub = ntb_config_pb2_grpc.NtbServiceStub(self.ntb_grpc_client.channel)
        start = time.time()
        grpc_ret = stub.batchDeviceConfig(request=request, metadata=self.ntb_grpc_client.metadata)
        end = time.time()
        print("batch vrf mac config cost {}s".format(end-start))

        # print(grpc_ret)

    def batch_vrf_vni_mtu_config(self, vrf_list, op, check=True):
        request = ntb_config_pb2.DeviceConfigRequest()
        for vrf in vrf_list:
            req = ntb_config_pb2.VrfVniMtuRequest()
            tmp = {
                "vrf": self._parse_vrf(vrf['vrf']),
                "vniMtuInfo": []
            }
            tmp["vniMtuInfo"].append({
                "vni": vrf['vni'],
                "mtu": vrf['mtu']
            })
            request.data.append(self.dict_to_grpc_any(tmp, req))
        request.type = ntb_config_pb2.BatchConfigType.BATCH_VNI_MTU
        request.opt = ntb_config_pb2.Operation.ADD  if op == "create" else ntb_config_pb2.Operation.DELETE

        stub = ntb_config_pb2_grpc.NtbServiceStub(self.ntb_grpc_client.channel)
        start = time.time()
        grpc_ret = stub.batchDeviceConfig(request=request, metadata=self.ntb_grpc_client.metadata)
        end = time.time()
        print("batch vrf vni mtu config cost {}s".format(end-start))

        # print(grpc_ret)

    def batch_vrf_mtu_config(self, vrf_list, op, check=True):
        request = ntb_config_pb2.DeviceConfigRequest()
        for vrf in vrf_list:
            req = ntb_config_pb2.VrfMtuRequest()
            tmp = {
                "vrfMtuInfos": []
            }
            tmp["vrfMtuInfos"].append({
                "vrf": self._parse_vrf(vrf['vrf']),
                "mtu": vrf['mtu']
            })
            request.data.append(self.dict_to_grpc_any(tmp, req))
        request.type = ntb_config_pb2.BatchConfigType.BATCH_VRF_MTU
        request.opt = ntb_config_pb2.Operation.ADD  if op == "create" else ntb_config_pb2.Operation.DELETE

        stub = ntb_config_pb2_grpc.NtbServiceStub(self.ntb_grpc_client.channel)
        start = time.time()
        grpc_ret = stub.batchDeviceConfig(request=request, metadata=self.ntb_grpc_client.metadata)
        end = time.time()
        print("batch vrf mtu config cost {}s".format(end-start))

        # print(grpc_ret)

    def set_hash_algo(self, algo_name, level="level1", expect_success=True):
        """
        设置全局ecmp算法
        :param algo_name:算法名, level: ecmp层级,目前只支持level1
        :return
        """
        dict_request = {
            "level": level,
            "algorithm": algo_name
        }
        grpc_ret = self.ntb_grpc_client.grpc_call("setGlobalHashAlgorithm", dict_request)
        if expect_success:
            self.assert_("set global ecmp {} algorithm {} faild".format(level, algo_name), grpc_ret["info"] == "success")
        else:
            self.assert_("set global ecmp {} algorithm {} faild".format(level, algo_name), grpc_ret["info"] == "failure")

    def set_hash_seed(self, seed, level="level1", expect_success=True):
        """
        设置全局ecmp seed
        :param seed: seed, level: ecmp层级,目前只支持level1
        :return
        """
        dict_request = {
            "level": level,
            "seed": seed
        }
        grpc_ret = self.ntb_grpc_client.grpc_call("setGlobalHashSeed", dict_request)
        if expect_success:
            self.assert_("set global ecmp {} seed {} faild".format(level, seed), grpc_ret["info"] == "success")
        else:
            self.assert_("set global ecmp {} seed {} faild".format(level, seed), grpc_ret["info"] == "failure")

    def get_hash_config_info(self, level="level1", fromhw=False):
        """
        获取全局ecmp hash配置信息
        :param level: ecmp层级,目前只支持level1, fromhw: 是否从硬件中获取. 
        :return
        """
        dict_request = {
            "level": level,
            "fromhw": fromhw
        }
        grpc_ret = self.ntb_grpc_client.grpc_call("getGlobalHashConfigInfo", dict_request)
        self.assert_("get global ecmp {} config info fromhw:{} faild".format(level, fromhw), grpc_ret["result"]["info"] == "success")
        return grpc_ret["algorithm"], grpc_ret["seed"], grpc_ret["defaultAlgorithm"], grpc_ret["defaultSeed"]

    def set_hash_algo_cli(self, algo_name):
        cmd_str = f"config ntb global ecmp hash level1 algorithm {algo_name}"
        out, err = self.ntb_ssh_client.exec_cmd(cmd_str)
        return out

    def set_hash_seed_cli(self, seed):
        cmd_str = f"config ntb global ecmp hash level1 seed {seed}"
        out, err = self.ntb_ssh_client.exec_cmd(cmd_str)
        return out

    def _parse_ecmp_config_info(self, text):
        text = text.decode("utf-8")
        lines = [line.strip() for line in text.split('\n') if line.strip()]
        header = next(line for line in lines if line.startswith("Level"))
        separator = next(line for line in lines if re.match(r'^-+', line))
        data = next(line for line in lines if re.match(r'^level\d', line))

        col_positions = [(m.start(), m.end()) for m in re.finditer(r'-+', separator)]

        headers = []
        for start, end in col_positions:
            headers.append(header[start:end].strip())

        values = []
        for start, end in col_positions:
            values.append(data[start:end].strip())
        res = dict(zip(headers, values))
        # print(res)
        seed = 0
        defseed = 0
        algorithm = ""
        defalgorithm = ""
        if "Algorithm" in res:
            algorithm = res["Algorithm"]

        if "Default Algorithm" in res:
            defalgorithm = res["Default Algorithm"]

        if "Seed" in res:
            seed = int(res["Seed"].split('/', 1)[0])
        if "Default Seed" in res:
            defseed = int(res["Default Seed"].split('/', 1)[0])
        return algorithm, seed, defalgorithm, defseed

    def get_hash_algo_cli(self, fromhw=False):
        cmd_str = f"show ntb global ecmp hash level1-config"
        if fromhw:
            cmd_str += " --fromhw"
        out, err = self.ntb_ssh_client.exec_cmd(cmd_str)
        return self._parse_ecmp_config_info(out)

    def _check_remark_dscp_res(self, vrfname, op, res, expect_res):
        in_device_remark_dscp_cfgs = {}
        cfgtypes = ["remarkdscprules"]
        in_device_cfgs = self.ntb_grpc_client.get_ntb_vrf_config(vrfname, cfgtypes)
        # print(in_device_cfgs)

        # 1.遍历配置核查结果,存储在in_device_remark_dscp_cfgs中
        for remark_dscp_entry in in_device_cfgs["remarkDscpRules"]:
            sip_str = "0.0.0.0/0"
            dip_str = "0.0.0.0/0"
            proto = 0 
            sport = 0 
            dport = 0 
            priority = 0
            tunnelid = 0
            tunneltype = 0
            direct = 0
            dscp = 0
            _, sip, sip_plen = self._parse_prefix_dict(remark_dscp_entry["match"]["srcip"])
            _, dip, dip_plen = self._parse_prefix_dict(remark_dscp_entry["match"]["dstip"])
            sip_str = "%s/%d" % (sip, sip_plen)
            dip_str = "%s/%d" % (dip, dip_plen)
            tmp_vrfname = remark_dscp_entry["match"]["vrf"]["vrfName"]
            tunnelid = remark_dscp_entry["match"]["tunnelId"]
            if remark_dscp_entry["match"]["tunnelType"] == "TUNNEL_TYPE_VXLAN":
                tunneltype = 1
            else:
                tunneltype = 2
            if remark_dscp_entry["match"]["direct"] == 'REMARK_DSCP_DIRECT_OUTBOUND':
                direct = 1
            else:
                direct = 0
            proto = remark_dscp_entry["match"]["proto"]
            sport = remark_dscp_entry["match"]["srcport"]
            dport = remark_dscp_entry["match"]["dstport"]
            priority = remark_dscp_entry["match"]["priority"]
            action = "noaction"
            if "action" in remark_dscp_entry:
                if "type" in remark_dscp_entry["action"]:
                    if remark_dscp_entry["action"]["type"] == "REMARK_DSCP_ACTION_REMARK_DSCP":
                        action = "remark"
            dscp   = remark_dscp_entry["data"]["dscp"]
            key = "%s-%d-%d-%d-%s-%s-%d-%d-%d-%d" % (
                tmp_vrfname, tunnelid, tunneltype, direct, sip_str, dip_str, proto, sport, dport, priority)
            in_device_remark_dscp_cfgs[key] = { "action" : action, "dscp" : dscp}

        # 2. 遍历每一个add/del操作的返回结果，根据key在in_device_remark_dscp_cfgs中检查是否存在，如果存在是否跟期望的结果一致
        for item in res:
            remark_dscp_entry = item["rule"]
            sip_str = "0.0.0.0/0"
            dip_str = "0.0.0.0/0"
            proto = 0 
            sport = 0 
            dport = 0 
            priority = 0
            tunnelid = 0
            tunneltype = 0
            direct = 0
            dscp = 0

            if "match" in remark_dscp_entry:
                if "vrf" in remark_dscp_entry["match"]:
                    if remark_dscp_entry["match"]["vrf"]["vrfName"] != vrfname:
                        self.log_info("%s remark-dscp-rules vrf not expected, expect %s but %s" % (
                            op, vrfname, remark_dscp_entry["match"]["vrf"]["vrfName"]))
                        return False
                if "tunnelId" in remark_dscp_entry["match"]:
                    tunnelid = remark_dscp_entry["match"]["tunnelId"]

                if "tunnelType" in remark_dscp_entry["match"]:
                    if remark_dscp_entry["match"]["tunnelType"] == "TUNNEL_TYPE_VXLAN":
                        tunneltype = 1
                    else:
                        tunneltype = 2
                if "direct" in remark_dscp_entry["match"]:
                    if remark_dscp_entry["match"]["direct"] == 'REMARK_DSCP_DIRECT_OUTBOUND':
                        direct = 1
                    else:
                        direct = 0

                if "srcip" in remark_dscp_entry["match"]:
                    _, sip, sip_plen = self._parse_prefix_dict_normalized(remark_dscp_entry["match"]["srcip"])
                    sip_str = "%s/%d" % (sip, sip_plen)
                if "dstip" in remark_dscp_entry["match"]:
                    _, dip, dip_plen = self._parse_prefix_dict_normalized(remark_dscp_entry["match"]["dstip"])
                    dip_str = "%s/%d" % (dip, dip_plen)
                if "proto" in remark_dscp_entry["match"]:
                    proto = remark_dscp_entry["match"]["proto"]
                if "srcport" in remark_dscp_entry["match"]:
                    sport = remark_dscp_entry["match"]["srcport"]
                if "dstport" in remark_dscp_entry["match"]:
                    dport = remark_dscp_entry["match"]["dstport"]
                if "priority" in remark_dscp_entry["match"]:
                    priority = remark_dscp_entry["match"]["priority"]

            action = "noaction"
            if "action" in remark_dscp_entry:
                if "type" in remark_dscp_entry["action"]:
                    if remark_dscp_entry["action"]["type"] == "REMARK_DSCP_ACTION_REMARK_DSCP":
                        action = "remark"
            dscp = 0
            if "data" in remark_dscp_entry:
                if "dscp" in remark_dscp_entry["data"]:
                    dscp =  remark_dscp_entry["data"]["dscp"]

            key = "%s-%d-%d-%d-%s-%s-%d-%d-%d-%d" % (
                vrfname, tunnelid, tunneltype, direct, sip_str, dip_str, proto, sport, dport, priority)

            e_res = expect_res[key]
            if e_res != item["result"]["info"]:
                self.log_info("%s remark-dscp %s result not expected, expect %s but %s" % (
                    op, key, e_res, item["result"]["info"]))
                return False
            if op == "create":
                if e_res == "success":
                    if key not in in_device_remark_dscp_cfgs:
                        self.log_info("%s remark-dscp %s success, but not set in device" % (op, key))
                        return False
                    if in_device_remark_dscp_cfgs[key]["action"] != action:
                        self.log_info("%s remark-dscp  %s success, but action %s inconsitent with %s in device" %
                                      (op, key, action, in_device_remark_dscp_cfgs[key]["action"]))
                        return False
                    if in_device_remark_dscp_cfgs[key]["action"] != action or in_device_remark_dscp_cfgs[key]["dscp"] != dscp:
                        self.log_info("%s remark-dscp  %s success, but dscp %s inconsitent with %s in device" %
                                      (op, key, dscp, in_device_remark_dscp_cfgs[key]["dscp"]))
                        return False
            else:
                if e_res == "success":
                    if key in in_device_remark_dscp_cfgs:
                        self.log_info("%sremark-dscp %s success, but still in device" % (op, key))
                        return False
        return True

    def _handle_remark_dscp_rules(self, vrfname, remark_dscp_rules, op):
        """
        下发remark dscp 配置
        """
        if len(remark_dscp_rules) == 0:
            return

        dict_request = {
            "rules": [
            ]
        }

        expect_res = {}
        for entry in remark_dscp_rules:
            item = {}
            item["match"] = {}
            item["action"] = {}
            item["data"] = {}
            sip_str = "0.0.0.0/0"
            dip_str = "0.0.0.0/0"
            proto = 0
            sport = 0
            dport = 0
            priority = 0
            direct = 1
            tunneltype = 1
            tunnelid = 0

            item["match"]["vrf"] = {
                "vrfName": vrfname
            }

            if "tunnelid" in entry:
                item["match"]["tunnelId"] = entry["tunnelid"]
                tunnelid = entry["tunnelid"]

            if "tunneltype" in entry:
                if entry["tunneltype"] == "vxlan":
                    tunneltype = 1
                else:
                    tunneltype = 2
                item["match"]["tunnelType"] = tunneltype
            if "direct" in entry:
                if  entry["direct"] == "inbound":
                    direct = 0
                else:
                    direct = 1
                item["match"]["direct"] = direct
            if "sip" in entry:
                item["match"]["srcip"] = self._encap_prefix_item(entry["sip"], entry["sip_mask_len"], "ipv4")
                sip_str = entry["sip"] + "/" + str(entry["sip_mask_len"])
                sip_str = str(ipaddress.ip_network(sip_str, strict=False))
            if "dip" in entry:
                item["match"]["dstip"] = self._encap_prefix_item(entry["dip"], entry["dip_mask_len"], "ipv4")
                dip_str = entry["dip"] + "/" + str(entry["dip_mask_len"])
                dip_str = str(ipaddress.ip_network(dip_str, strict=False))
            if "proto" in entry:
                item["match"]["proto"] = entry["proto"]
                proto = entry["proto"]
            if "sport" in entry:
                item["match"]["srcport"] = entry["sport"]
                sport = entry["sport"]
            if "dport" in entry:
                item["match"]["dstport"] = entry["dport"]
                dport = entry["dport"]
            if "priority" in entry:
                item["match"]["priority"] = entry["priority"]
                priority = entry["priority"]

            if "action" in entry:
                if entry["action"] == "remark":
                    item["action"]["type"] = 1
                else:
                    item["action"]["type"] = 0
            if "data" in entry:
                item["data"]["dscp"] = entry["data"]["dscp"]

            dict_request["rules"].append(item)

            expect_key = "%s-%d-%d-%d-%s-%s-%d-%d-%d-%d" % (
                vrfname, tunnelid, tunneltype, direct, sip_str, dip_str, proto, sport, dport, priority)
            if "expect_res" in entry:
                expect_res[expect_key] = entry["expect_res"]
            else:
                expect_res[expect_key] = "success"
        if op == "create":
            grpc_ret = self.ntb_grpc_client.grpc_call("addRemarkDscpRule", dict_request)
        else:
            grpc_ret = self.ntb_grpc_client.grpc_call("delRemarkDscpRule", dict_request)
        self.assert_("%s remark dscp rule faild, not expected" % (op),
                        self._check_remark_dscp_res(vrfname, op, grpc_ret["remarkDscpRuleCfgResults"], expect_res))

    def add_remark_dscp_rule(self, vrfname, remark_dscp_rules):
        """
        添加  remark dscp rules
        :param remark_dscp_rules: remark dscp rules信息列表
            item: eg: { "tunnelid": 1, "tunneltype": "vxlan", "direct": "inbound",
                        "sip": "1.1.1.1", "sip_mask_len": 24,
                        "dip": "1.1.1.2", "dip_mask_len": 24,
                        "proto": 0, "sport": 0, "dport":0, "priority":0,
                        "action": "remark", "dscp": 10,
                        expect_res": "success"}
        :return
        """
        self._handle_remark_dscp_rules(vrfname, remark_dscp_rules, "create")

    def del_remark_dscp_rule(self, vrfname, remark_dscp_rules):
        """
        删除 remark dscp rules
        :param remark_dscp_rules: remark dscp rules信息列表
            item: eg: {"tunnelid": 1, "tunneltype": "vxlan", "direct": "inbound",
                        "sip": "1.1.1.1", "sip_mask_len": 24,
                        "dip": "1.1.1.2", "dip_mask_len": 24,
                        "proto": 0, "sport": 0, "dport":0, "priority":0,
                        "action": "remark", "dscp": 10,
                        expect_res": "success"}
        :return
        """
        self._handle_remark_dscp_rules(vrfname, remark_dscp_rules, "delete")

    def get_remark_dscp_rule_stats(self, vrfname, remark_dscp_rules):
        """
        获取指定remark dscp 规则统计
        """
        
        if len(remark_dscp_rules) == 0:
            return

        dict_request = {
            "rules": [
            ]
        }

        for entry in remark_dscp_rules:
            item = {}
            item["match"] = {}
            item["action"] = {}
            item["data"] = {}
            direct = 1
            tunneltype = 1

            item["match"]["vrf"] = {
                "vrfName": vrfname
            }

            if "tunnelid" in entry:
                item["match"]["tunnelId"] = entry["tunnelid"]

            if "tunneltype" in entry:
                if entry["tunneltype"] == "vxlan":
                    tunneltype = 1
                else:
                    tunneltype = 2
                item["match"]["tunnelType"] = tunneltype
            if "direct" in entry:
                if  entry["direct"] == "inbound":
                    direct = 0
                else:
                    direct = 1
                item["match"]["direct"] = direct
            if "sip" in entry:
                item["match"]["srcip"] = self._encap_prefix_item(entry["sip"], entry["sip_mask_len"], "ipv4")
            if "dip" in entry:
                item["match"]["dstip"] = self._encap_prefix_item(entry["dip"], entry["dip_mask_len"], "ipv4")
            if "proto" in entry:
                item["match"]["proto"] = entry["proto"]
            if "sport" in entry:
                item["match"]["srcport"] = entry["sport"]
            if "dport" in entry:
                item["match"]["dstport"] = entry["dport"]
            if "priority" in entry:
                item["match"]["priority"] = entry["priority"]

            if "action" in entry:
                if entry["action"] == "remark":
                    item["action"]["type"] = 1
                else:
                    item["action"]["type"] = 0
            if "data" in entry:
                item["data"]["dscp"] = entry["data"]["dscp"]

            dict_request["rules"].append(item)

        grpc_ret = self.ntb_grpc_client.grpc_call("getRemarkDscpCounter", dict_request)
        self.assert_("get vrf %s remark dscp rule stat faild, not expected" % (vrfname), grpc_ret["result"]["info"] == "success")
        return grpc_ret["counters"]

    def get_vrf_remark_dscp_rule_stats(self, vrfname=""):
        """
        获取指定vrf的remark dscp 规则统计
        """
        dict_request = {
            "vrfName": vrfname
        }
        grpc_ret = self.ntb_grpc_client.grpc_call("getRemarkDscpCounterByvrf", dict_request)
        self.assert_("get vrf %s remark dscp rule stat faild, not expected" % (vrfname), grpc_ret["result"]["info"] == "success")
        return grpc_ret["counters"]

    def get_all_vrf_remark_dscp_rule_stats(self):
        """
        获取所有vrf的remark dscp 规则统计
        """
        dict_request = {}
        grpc_ret = self.ntb_grpc_client.grpc_call("getRemarkDscpCounterAll", dict_request)
        self.assert_("get all vrf remark dscp rule stat faild, not expected", grpc_ret["result"]["info"] == "success")
        return grpc_ret["counters"]

    def clear_remark_dscp_rule_stats(self, vrfname, remark_dscp_rules):
        """
        清除指定remark dscp 规则统计
        """
        if len(remark_dscp_rules) == 0:
            return

        dict_request = {
            "rules": [
            ]
        }

        for entry in remark_dscp_rules:
            item = {}
            item["match"] = {}
            item["action"] = {}
            item["data"] = {}
            direct = 1
            tunneltype = 1

            item["match"]["vrf"] = {
                "vrfName": vrfname
            }

            if "tunnelid" in entry:
                item["match"]["tunnelId"] = entry["tunnelid"]

            if "tunneltype" in entry:
                if entry["tunneltype"] == "vxlan":
                    tunneltype = 1
                else:
                    tunneltype = 2
                item["match"]["tunnelType"] = tunneltype
            if "direct" in entry:
                if  entry["direct"] == "inbound":
                    direct = 0
                else:
                    direct = 1
                item["match"]["direct"] = direct
            if "sip" in entry:
                item["match"]["srcip"] = self._encap_prefix_item(entry["sip"], entry["sip_mask_len"], "ipv4")
            if "dip" in entry:
                item["match"]["dstip"] = self._encap_prefix_item(entry["dip"], entry["dip_mask_len"], "ipv4")
            if "proto" in entry:
                item["match"]["proto"] = entry["proto"]
            if "sport" in entry:
                item["match"]["srcport"] = entry["sport"]
            if "dport" in entry:
                item["match"]["dstport"] = entry["dport"]
            if "priority" in entry:
                item["match"]["priority"] = entry["priority"]

            if "action" in entry:
                if entry["action"] == "remark":
                    item["action"]["type"] = 1
                else:
                    item["action"]["type"] = 0
            if "data" in entry:
                item["data"]["dscp"] = entry["data"]["dscp"]

            dict_request["rules"].append(item)
        grpc_ret = self.ntb_grpc_client.grpc_call("clearRemarkDscpCounter", dict_request)
        self.assert_("clear vrf %s remark dscp rule stat faild, not expected" % (vrfname), grpc_ret["result"]["info"] == "success")
        return

    def clear_vrf_remark_dscp_rule_stats(self, vrfname=""):
        """
        清除指定vrf的remark dscp 规则统计
        """
        dict_request = {
            "vrfName": vrfname
        }
        grpc_ret = self.ntb_grpc_client.grpc_call("clearRemarkDscpCounterByvrf", dict_request)
        self.assert_("clear vrf %s remark dscp rule stat faild, not expected" % (vrfname), grpc_ret["info"] == "success")
        return

    def clear_all_vrf_remark_dscp_rule_stats(self):
        """
        清除所有vrf的remark dscp 规则统计
        """
        dict_request = {}
        grpc_ret = self.ntb_grpc_client.grpc_call("clearRemarkDscpCounterAll", dict_request)
        self.assert_("clear all vrf remark dscp rule stat faild, not expected", grpc_ret["info"] == "success")
        return

    def gdb_insert_break(self, channel, function_name, ret=-1, count=1):
        """
        通过gdb插入断点, 修改返回值
        :param channel: ssh channel
        :param function_name: 函数名称
        :param ret: 劫持的返回值
        :param count: 第几次劫持
        :return
        """
        # 写入gdb脚本
        self.ntb_ssh_client.exec_cmd('printf "set pagination off\nset height 0\nset \$count = 0\nbreak %s\ncommands\nset \$count = \$count + 1\nif \$count == %d\n    set \$rax = %d\n    return\nend\nif \$count == %d\n    detach\n    quit\nend\ncontinue\nend\n" > /tmp/gdb_script' % (function_name, count, ret, count))
        # 获取ntb_cntl进程pid
        out, err = self.ntb_ssh_client.exec_cmd('pidof ntb_cntl')
        ntb_cntl_pid = out.decode().strip()
        if not ntb_cntl_pid:
            self.assert_("ntb_cntl process not found", False)
            return False
        # 执行gdb脚本
        self.ntb_ssh_client.send(channel, 'gdb -p {} -x /tmp/gdb_script'.format(ntb_cntl_pid))
        time.sleep(10)
        # 跳过分页继续执行
        self.ntb_ssh_client.send(channel, 'c\n')
        time.sleep(3)
        # 继续执行
        self.ntb_ssh_client.send(channel, 'continue\n')
        # out = self.ntb_ssh_client.recv(channel)

    def check_hw_nhop_obj(self, expect_num):
        table = self.get_hw_table_spec()
        self.assert_("NTB_NHOP_OBJ should be %d, but is %d" % (expect_num, table['NTB_NHOP_OBJ']['curCnt']), table['NTB_NHOP_OBJ']['curCnt'] == expect_num)

    def check_hw_ecmp_obj(self, expect_num):
        table = self.get_hw_table_spec()
        self.assert_("NTB_ECMP_OBJ should be %d, but is %d" % (expect_num, table['NTB_ECMP_OBJ']['curCnt']), table['NTB_ECMP_OBJ']['curCnt'] == expect_num)

    def check_hw_ecmp_member_obj(self, expect_num):
        table = self.get_hw_table_spec()
        self.assert_("NTB_ECMP_MBR_OBJ should be %d, but is %d" % (expect_num, table['NTB_ECMP_MBR_OBJ']['curCnt']), table['NTB_ECMP_MBR_OBJ']['curCnt'] == expect_num)

    def check_hw_lpm_obj(self, expect_num):
        table = self.get_hw_table_spec()
        self.assert_("NTB_FIB_LPM_OBJ should be %d, but is %d" % (expect_num, table['NTB_FIB_LPM_OBJ']['curCnt']), table['NTB_FIB_LPM_OBJ']['curCnt'] == expect_num)

    def get_hw_ecmp_obj(self):
        table = self.get_hw_table_spec()
        print("ecmp cur cnt: {}, max cnt: {}".format(table['NTB_ECMP_OBJ']['curCnt'], table['NTB_ECMP_OBJ']['maxCnt']))
        return table['NTB_ECMP_OBJ']['curCnt'], table['NTB_ECMP_OBJ']['maxCnt']

    def get_hw_ecmp_member_obj(self):
        table = self.get_hw_table_spec()
        print("ecmp member cur cnt: {}, max cnt: {}".format(table['NTB_ECMP_MBR_OBJ']['curCnt'], table['NTB_ECMP_MBR_OBJ']['maxCnt']))
        return table['NTB_ECMP_MBR_OBJ']['curCnt'], table['NTB_ECMP_MBR_OBJ']['maxCnt']

    def get_hw_nhop_obj(self):
        table = self.get_hw_table_spec()
        print("nexthop cur cnt: {}, max cnt: {}".format(table['NTB_NHOP_OBJ']['curCnt'], table['NTB_NHOP_OBJ']['maxCnt']))
        return table['NTB_NHOP_OBJ']['curCnt'], table['NTB_NHOP_OBJ']['maxCnt']

    def get_hw_lpm_obj(self):
        table = self.get_hw_table_spec()
        print("lpm cur cnt: {}, max cnt: {}".format(table['NTB_FIB_LPM_OBJ']['curCnt'], table['NTB_FIB_LPM_OBJ']['maxCnt']))
        return table['NTB_FIB_LPM_OBJ']['curCnt'], table['NTB_FIB_LPM_OBJ']['maxCnt']

class NTBTrafficTestBase(NTBTestBase):
    """NTB打流测试基类, 封装PTF相关的打流函数
    """

    def pre_test(self, enable_spirent=False, enable_nfc=False):
        super(NTBTrafficTestBase, self).pre_test()
        self.add_vxlan_and_gre_filter()
        self.qta_ip = ""
        self.qta_mac = ""
        self.qta_gw_mac = ""
        self.ntb_term_vip = ""
        self.ntb_fwd_vip = ""
        self.qta_send_ov_smac = "4a:4f:c9:f6:a6:68"
        self.qta_send_ov_dmac = "4a:4f:c9:f6:a6:67"
        # fake mac if not set vrf mac
        self.ntb_send_ov_smac = "3c:fd:fe:29:cb:c2"
        self.ntb_send_ov_dmac = "3c:fd:fe:29:cb:d2"
        self.spirent_enabled = enable_spirent
        self.nfc_enabled = enable_nfc
        self.instance_name = ""
        # init spirent config
        if self.spirent_enabled:
            self.spirent_grpc_client.connect()
            self.instance_name = self.spirent_create_instance()
        self.ntb_ssh_client.connect()
        if self.nfc_enabled:
            self.nfc_grpc_client.connect()

    def post_test(self):
        self.reset_all_filters()
        if self.spirent_enabled:
            self.spirent_delete_instance()
        super(NTBTrafficTestBase, self).post_test()

    def enable_spirent(self):
        if self.spirent_enabled:
            return
        self.spirent_grpc_client.connect()
        self.instance_name = self.spirent_create_instance()
        self.spirent_enabled = True

    def init_traffic_env(self, qta_ip, qta_mac, qta_gw_mac, ntb_term_vip, ntb_fwd_vip):
        """
        初始化打流环境
        :param qta_ip: qta 打流设备IP
        :param qta_mac: qta打流设备Mac
        :param qta_gw_mac: qta打流设备对应的网关mac
        :param ntb_terminate_vip: NTB终结IP, ptf打流使用的目的IP 
        :param ntb_fwd_vip: ntb转发使用的vip, 校验回包时作为源ip 
        :return
        """
        self.qta_ip = qta_ip
        self.qta_mac = qta_mac
        self.qta_gw_mac = qta_gw_mac
        self.ntb_term_vip = ntb_term_vip
        self.ntb_fwd_vip = ntb_fwd_vip

    def create_vxlan_pkt_inner_mpls(self, vni):
        """
        构造发送NTB的内层为mpls的报文
        :param vni: vni值
        :return pkt
        """
        _sip = self.qta_ip
        _dip = self.ntb_term_vip
        underlay = Ether(src=self.qta_mac, dst=self.qta_gw_mac) / IP(dst=_dip, src=_sip)
        vxlanh = UDP(dport=4789, sport=12345) / VXLAN(vni=vni) / Ether(src=self.qta_send_ov_smac,
                                                                                            dst=self.qta_send_ov_dmac,
                                                                                            type=0x8847)
        return underlay / vxlanh

    def create_vxlan_pkt_send_to_ntb(self, vni, inner_frame=None, sip="", dip="", sport=12345, inner_eth_src="", inner_eth_dst="", inner_eth_type=0):
        """
        构造发送NTB的vxlan流量
        :param vni: vni值
        :param sport: underlay 源端口, 默认值12345
        :param inner_frame: overlay 报文
        :return pkt
        """
        if (sip == ""):
            _sip = self.qta_ip
        else:
            _sip = sip
        if (dip == ""):
            _dip = self.ntb_term_vip
        else:
            _dip = dip

        if inner_eth_src == "":
            _inner_eth_src = self.qta_send_ov_smac
        else:
            _inner_eth_src = inner_eth_src

        if inner_eth_dst == "":
            _inner_eth_dst = self.qta_send_ov_dmac
        else:
            _inner_eth_dst = inner_eth_dst
        
        if inner_eth_type == 0:
            inner_ether = Ether(src=_inner_eth_src, dst=_inner_eth_dst) 
        else:
            inner_ether = Ether(src=_inner_eth_src, dst=_inner_eth_dst, type=inner_eth_type) 

        underlay = Ether(src=self.qta_mac, dst=self.qta_gw_mac) / IP(dst=_dip, src=_sip)
        vxlanh = UDP(dport=4789, sport=sport) / VXLAN(vni=vni)
        if inner_frame == None:
            pkt = underlay / vxlanh / inner_ether 
        else:
            pkt = underlay / vxlanh / inner_ether/ inner_frame 
        return pkt

    def create_vxlan_pkt_recv_from_ntb(self, vni, dscp=26, inner_frame=None, sport=0, vrf_mac="", ov_dst_mac="", src_ip="", inner_eth_type=0):
        """
        构造预期从NTB接收的vxlan报文
        :param vni: vni值
        :param inner_frame: overlay 报文
        :param sport: 默认为0, 不关注源端口配置
        :param vrf_mac: 默认为空,如果设置了vrfmac需要指定
        :param ov_dst_mac: 默认为空,如果设置gateway, 需要指定该参数
        :return pkt
        """
        ntb_ov_src_mac = self.ntb_send_ov_smac
        ntb_ov_dst_mac = self.ntb_send_ov_dmac
        ntb_src_ip = self.ntb_fwd_vip
        if vrf_mac != "":
            ntb_ov_src_mac = vrf_mac
        if ov_dst_mac != "":
            ntb_ov_dst_mac = ov_dst_mac
        if src_ip != "":
            ntb_src_ip = src_ip

        if inner_eth_type == 0:
            inner_ether = Ether(src=ntb_ov_src_mac, dst=ntb_ov_dst_mac) 
        else:
            inner_ether = Ether(src=ntb_ov_src_mac, dst=ntb_ov_dst_mac, type=inner_eth_type) 

        underlay = Ether(src=self.qta_gw_mac, dst=self.qta_mac) / IP(dst=self.qta_ip,
                                                                                   src=ntb_src_ip, tos=(dscp<<2) & 0xff)
        vxlanh = UDP(sport=sport, dport=4789, chksum=0) / VXLAN(vni=vni, flags="Instance") 

        if inner_frame == None:
            pkt = underlay / vxlanh / inner_ether 
        else:
            pkt = underlay / vxlanh / inner_ether/ inner_frame 
        return pkt

    def create_gre_pkt_inner_mpls(self, vpcid):
        """
        构造发送NTB的gre流量,内层为mpls报文
        :param vpcid: vpcid值
        :return pkt
        """
        _sip = self.qta_ip
        underlay = Ether(src=self.qta_mac, dst=self.qta_gw_mac) / IP(dst=self.ntb_term_vip, src=_sip)
        greh = GRE(key_present=1, key=vpcid, proto=0x8847)
        return underlay / greh

    def create_gre_pkt_send_to_ntb(self, vpcid, inner_frame, vmip="", sip=""):
        """
        构造发送NTB的gre流量
        :param vpcid: vpcid值
        :param inner_frame: overlay 报文
        :return pkt
        """
        if (sip == ""):
            _sip = self.qta_ip
        else:
            _sip = sip
        underlay = Ether(src=self.qta_mac, dst=self.qta_gw_mac) / IP(dst=self.ntb_term_vip, src=_sip)
        if vmip == "":
            greh = GRE(key_present=1, key=vpcid)
        else:
            vmip_bits = vmip.split('.')
            chksum = (int(vmip_bits[0]) << 8) + int(vmip_bits[1])
            offset = (int(vmip_bits[2]) << 8) + int(vmip_bits[3])
            greh = GRE(chksum_present=1, chksum=chksum, offset=offset, key_present=1, key=vpcid)
        return underlay / greh / inner_frame

    def create_gre_pkt_recv_from_ntb(self, vpcid, inner_frame, gre_version=0, gre_sip="", vmip=""):
        """
        构造预期从NTB接收的gre报文
        :param sport: 源端口号
        :param vni: vni值
        :param gre_version: gre 版本号, 默认为0
        :param inner_frame: overlay 报文
        :param vrf_mac: 默认为空,如果设置了vrfmac需要指定
        :param vmip: vmip 默认为空
        :return pkt
        """
        ntb_sip = self.ntb_fwd_vip
        if gre_sip != "":
            ntb_sip = gre_sip
        underlay = Ether(src=self.qta_gw_mac, dst=self.qta_mac) / IP(dst=self.qta_ip, src=ntb_sip)
        if vmip == "":
            greh = GRE(key_present=1, version=gre_version, key=vpcid)
        else:
            vmip_bits = vmip.split('.')
            chksum = (int(vmip_bits[0]) << 8) + int(vmip_bits[1])
            offset = (int(vmip_bits[2]) << 8) + int(vmip_bits[3])
            greh = GRE(chksum_present=1, version=gre_version, chksum=chksum, offset=offset, key_present=1,
                              key=vpcid)
        return underlay / greh / inner_frame

    def create_frag1_udp_pkt(self, dip, sip, ttl=63, dscp=0, sport=1234, dport=5678,
                             payload=None, chksum=None, pkt_len=100, udp_len=None):
        """
        构造发送NTB的分片报文（首片）
        :param dip: 目的ip
        :param sip: 源ip
        :param ttl: 可以不指定, 默认63
        :param sport: 可以不指定, 默认1234
        :param dport: 可以不指定, 默认5678
        :param payload: 可以不指定, 默认None
        :param chksum: 可以不指定, 默认None
        :param pkt_len: 可以不指定, 默认100
        :param udp_len: udp的长度, 可以不指定, 默认为payload+l4+ip
        :return pkt
        """
        if udp_len != None:
            pkt = IP(dst=dip, src=sip, ttl=ttl, flags=0x1, tos=(dscp<<2)) / UDP(sport=sport, dport=dport, chksum=chksum,
                                                                               len=udp_len)
        else:
            pkt = IP(dst=dip, src=sip, ttl=ttl, flags=0x1, tos=(dscp<<2)) / UDP(sport=sport, dport=dport, chksum=chksum)
        if payload:
            pkt = pkt / payload
        if (pkt_len - len(pkt)) > 0:
            pkt = pkt / codecs.decode("".join(["%02x" % (x % 256) for x in range(pkt_len - len(pkt))]), "hex")
        return pkt

    def create_frag1_udp_pkt_ipv6(self, dip, sip, hlim=63, sport=1234, dport=5678,
                             payload=None, chksum=None, pkt_len=100, udp_len=None):
        """
        构造发送NTB的分片报文（首片）
        :param dip: 目的ip
        :param sip: 源ip
        :param ttl: 可以不指定, 默认63
        :param sport: 可以不指定, 默认1234
        :param dport: 可以不指定, 默认5678
        :param payload: 可以不指定, 默认None
        :param chksum: 可以不指定, 默认None
        :param pkt_len: 可以不指定, 默认100
        :param udp_len: udp的长度, 可以不指定, 默认为payload+l4+ip
        :return pkt
        """
        if udp_len != None:
            pkt = IPv6(dst=dip, src=sip, hlim=hlim)/IPv6ExtHdrFragment(m=1) / UDP(sport=sport, dport=dport, chksum=chksum,
                                                                               len=udp_len)
        else:
            pkt = IPv6(dst=dip, src=sip, hlim=hlim)/IPv6ExtHdrFragment(m=1) / UDP(sport=sport, dport=dport, chksum=chksum)
        if payload:
            pkt = pkt / payload
        if (pkt_len - len(pkt)) > 0:
            pkt = pkt / codecs.decode("".join(["%02x" % (x % 256) for x in range(pkt_len - len(pkt))]), "hex")
        return pkt

    def create_frag2_udp_pkt(self, dip, sip, ttl=63, dscp=0, sport=1234, dport=5678,
                             payload=None, pkt_len=100, flags=0, frag=0x32, data_offset=392):
        """
        构造发送NTB的分片报文（尾片）
        :param dip: 目的ip
        :param sip: 源ip
        :param ttl: 可以不指定, 默认63
        :param sport: 可以不指定, 默认1234
        :param dport: 可以不指定, 默认5678
        :param payload: 可以不指定, 默认None
        :param pkt_len: 可以不指定, 默认100
        :return pkt
        """
        pkt = IP(dst=dip, src=sip, ttl=ttl, flags=flags, frag=frag, proto=17, tos=(dscp<<2))
        if payload:
            pkt = pkt / payload
        if (pkt_len - len(pkt)) > 0:
            pkt = pkt / codecs.decode("".join(["%02x" % ((x + data_offset % 256) % 256) for x in range(pkt_len - len(pkt))]), "hex")
        return pkt

    def create_frag1_icmp_pkt(self, dip, sip, ttl=63, dscp=0, icmp_type=8, icmp_code=0,
                             payload=None, pkt_len=100):
        """
        构造发送NTB的分片报文（首片）
        :param dip: 目的ip
        :param sip: 源ip
        :param ttl: 可以不指定, 默认63
        :param icmp_type: 可以不指定, 默认icmp_echo
        :param icmp_code: 可以不指定, 默认icmp_echo
        :param payload: 可以不指定, 默认None
        :param pkt_len: 可以不指定, 默认100
        :return pkt
        """
        pkt = IP(dst=dip, src=sip, ttl=ttl, flags=0x1, tos=(dscp<<2)) / ICMP(type=icmp_type, code=icmp_code)
        if payload:
            pkt = pkt / payload
        if (pkt_len - len(pkt)) > 0:
            pkt = pkt / codecs.decode("".join(["%02x" % (x % 256) for x in range(pkt_len - len(pkt))]), "hex")
        return pkt

    def create_frag2_icmp_pkt(self, dip, sip, ttl=63, dscp=0,
                             payload=None, pkt_len=100, flags=0, frag=0x32, data_offset=392):
        """
        构造发送NTB的分片报文（尾片）
        :param dip: 目的ip
        :param sip: 源ip
        :param ttl: 可以不指定, 默认63
        :param payload: 可以不指定, 默认None
        :param pkt_len: 可以不指定, 默认100
        :return pkt
        """
        pkt = IP(dst=dip, src=sip, ttl=ttl, flags = flags, frag=frag, proto=1, tos=(dscp<<2))
        if payload:
            pkt = pkt / payload
        if (pkt_len - len(pkt)) > 0:
            pkt = pkt / codecs.decode("".join(["%02x" % ((x + data_offset % 256) % 256) for x in range(pkt_len - len(pkt))]), "hex")
        return pkt

    def create_frag1_ip_only_pkt(self, dip, sip, proto_id=0, ttl=63, dscp=0,
                             payload=None, pkt_len=100):
        """
        构造发送NTB的分片报文（首片）
        :param dip: 目的ip
        :param sip: 源ip
        :param ttl: 可以不指定, 默认63
        :param payload: 可以不指定, 默认None
        :param pkt_len: 可以不指定, 默认100
        :return pkt
        """
        pkt = IP(dst=dip, src=sip, ttl=ttl, flags=0x1, proto=proto_id, tos=(dscp<<2))
        if payload:
            pkt = pkt / payload
        if (pkt_len - len(pkt)) > 0:
            pkt = pkt / codecs.decode("".join(["%02x" % (x % 256) for x in range(pkt_len - len(pkt))]), "hex")
        return pkt

    def create_frag2_ip_only_pkt(self, dip, sip, proto_id=0, ttl=63, dscp=0,
                             payload=None, pkt_len=100, flags=0, frag=0x32, data_offset=400):
        """
        构造发送NTB的分片报文（尾片）
        :param dip: 目的ip
        :param sip: 源ip
        :param ttl: 可以不指定, 默认63
        :param payload: 可以不指定, 默认None
        :param pkt_len: 可以不指定, 默认100
        :return pkt
        """
        pkt = IP(dst=dip, src=sip, ttl=ttl, flags = flags, frag=frag, proto=proto_id, tos=(dscp<<2))
        if payload:
            pkt = pkt / payload
        if (pkt_len - len(pkt)) > 0:
            pkt = pkt / codecs.decode("".join(["%02x" % ((x + data_offset % 256) % 256) for x in range(pkt_len - len(pkt))]), "hex")
        return pkt

    def create_frag2_udp_pkt_ipv6(self, dip, sip, hlim=63, sport=1234, dport=5678,
                             payload=None, pkt_len=100):
        """
        构造发送NTB的分片报文（尾片）
        :param dip: 目的ip
        :param sip: 源ip
        :param ttl: 可以不指定, 默认63
        :param sport: 可以不指定, 默认1234
        :param dport: 可以不指定, 默认5678
        :param payload: 可以不指定, 默认None
        :param pkt_len: 可以不指定, 默认100
        :return pkt
        """
        pkt = IPv6(dst=dip, src=sip, hlim=hlim)/IPv6ExtHdrFragment(offset=0x32, m=0, nh=17)
        if payload:
            pkt = pkt / payload
        if (pkt_len - len(pkt)) > 0:
            pkt = pkt / codecs.decode("".join(["%02x" % ((x + 0x88) % 256) for x in range(pkt_len - len(pkt))]), "hex")
        return pkt

    def create_frag1_tcp_pkt(self, dip, sip, ttl=63, sport=1234, dport=5678, tcp_flags=0, tcp_options="",
                             payload=None, chksum=None, pkt_len=100):
        """
        构造发送NTB的分片报文（首片）
        :param dip: 目的ip
        :param sip: 源ip
        :param ttl: 可以不指定, 默认63
        :param sport: 可以不指定, 默认1234
        :param dport: 可以不指定, 默认5678
        :param payload: 可以不指定, 默认None
        :param chksum: 可以不指定, 默认None
        :param pkt_len: 可以不指定, 默认100
        :param udp_len: udp的长度, 可以不指定, 默认为payload+l4+ip
        :return pkt
        """
        pkt = IP(dst=dip, src=sip, ttl=ttl, flags=0x1) / TCP(sport=sport, dport=dport, flags=tcp_flags,
                                                                           options=tcp_options)
        if payload:
            pkt = pkt / payload
        if (pkt_len - len(pkt)) > 0:
            pkt = pkt / codecs.decode("".join(["%02x" % (x % 256) for x in range(pkt_len - len(pkt))]), "hex")
        return pkt

    def create_frag2_tcp_pkt(self, dip, sip, ttl=63,
                             payload=None, pkt_len=100):
        """
        构造发送NTB的分片报文（尾片）
        :param dip: 目的ip
        :param sip: 源ip
        :param ttl: 可以不指定, 默认63
        :param sport: 可以不指定, 默认1234
        :param dport: 可以不指定, 默认5678
        :param payload: 可以不指定, 默认None
        :param pkt_len: 可以不指定, 默认100
        :return pkt
        """
        pkt = IP(dst=dip, src=sip, ttl=ttl, frag=0x32, proto=6)
        if payload:
            pkt = pkt / payload
        if (pkt_len - len(pkt)) > 0:
            pkt = pkt / codecs.decode("".join(["%02x" % ((x + 0x54) % 256) for x in range(pkt_len - len(pkt))]), "hex")
        return pkt

    def create_double_vxlan_pkt_send_to_ntb(self, vni, dip, sip, inner_frame, ttl=64, sport=12345, payload=None,
                                            pkt_len=500):
        """
        构造发送NTB的双层vxlan流量
        packet:
            Ether()/IP()/UDP()/Vxlan()/Ether()/IP()/UDP()/Vxlan()/Ether()/IP()/PayLoad()
        """
        underlay = Ether(src=self.qta_mac, dst=self.qta_gw_mac) / IP(dst=self.ntb_term_vip,
                                                                                   src=self.qta_ip)
        outerVxlanh = UDP(dport=4789, sport=sport) / VXLAN(vni=vni,flags="Instance")

        overlay = Ether(src=self.qta_send_ov_smac, dst=self.qta_send_ov_dmac) / IP(dst=dip, src=sip,
                                                                                                 ttl=ttl)
        innerVxlanh = UDP(dport=4789, sport=sport) / VXLAN(vni=1000,flags="Instance")

        inner_frame = Ether() / inner_frame
        # inner_frame = inner_frame.hex()
        pkt = underlay / outerVxlanh / overlay / innerVxlanh / inner_frame
        return pkt

    def create_double_vxlan_pkt_recv_from_ntb(self, vni, dip, sip, inner_frame, ttl=63, sport=12345, payload=None,
                                              pkt_len=500, vrf_mac="", ov_dst_mac=""):
        """
        构造预期的双层vxlan流量
        packet:
            Ether()/IP()/UDP()/Vxlan()/Ether()/IP()/UDP()/Vxlan()/Ether()/IP()/PayLoad()
        """
        ntb_ov_src_mac = self.ntb_send_ov_smac
        ntb_ov_dst_mac = self.ntb_send_ov_dmac
        if vrf_mac != "":
            ntb_ov_src_mac = vrf_mac
        if ov_dst_mac != "":
            ntb_ov_dst_mac = ov_dst_mac

        underlay = Ether(src=self.qta_gw_mac, dst=self.qta_mac) / IP(dst=self.qta_ip,
                                                                                   src=self.ntb_fwd_vip)
        outerVxlanh = UDP(dport=4789, sport=sport, chksum=0) / VXLAN(vni=vni,flags="Instance")

        overlay = Ether(src=ntb_ov_src_mac, dst=ntb_ov_dst_mac) / IP(dst=dip, src=sip, ttl=ttl)
        innerVxlanh = UDP(dport=4789, sport=sport) / VXLAN(vni=1000,flags="Instance")

        inner_frame = Ether() / inner_frame
        # inner_frame = inner_frame.hex()
        pkt = underlay / outerVxlanh / overlay / innerVxlanh / inner_frame
        return pkt

    def create_double_gre_pkt_send_to_ntb(self, vpcid, sip, dip, inner_frame, ttl=64, payload=None, pkt_len=500):
        """
        构造发送NTB的双层gre流量
        packet:
            Ether()/IP()/GRE()/IP()/GRE()/IP()/PayLoad()
        """
        underlay = Ether(src=self.qta_mac, dst=self.qta_gw_mac) / IP(dst=self.ntb_term_vip,
                                                                                   src=self.qta_ip)
        outerGre = GRE(key_present=1, key=vpcid)

        innerGre = IP(dst=dip, src=sip, ttl=ttl) / GRE(key_present=1, key=1000)
        # inner_frame = inner_frame.hex()
        pkt = underlay / outerGre / innerGre / inner_frame
        return pkt

    def create_double_gre_pkt_recv_from_ntb(self, vpcid, sip, dip, inner_frame, ttl=63, gre_version=0, gre_sip="",
                                            payload=None, pkt_len=500):
        """
        构造预期的双层gre流量
        packet:
            Ether()/IP()/GRE()/IP()/GRE()/IP()/PayLoad()
        """
        ntb_sip = self.ntb_fwd_vip
        if gre_sip != "":
            ntb_sip = gre_sip
        underlay = Ether(src=self.qta_gw_mac, dst=self.qta_mac) / IP(dst=self.qta_ip, src=ntb_sip)
        outerGre = GRE(key_present=1, version=gre_version, key=vpcid)

        innerGre = IP(dst=dip, src=sip, ttl=ttl) / GRE(key_present=1, key=1000)
        # inner_frame = inner_frame.hex()
        pkt = underlay / outerGre / innerGre / inner_frame
        return pkt

    def create_ipv6_vxlan_pkt(self, sip, dip, inner_frame, vni=12345678, hlim=64, sport=0):
        """
        构造双层vxlan报文
        :param vni: vni值
        :param inner_frame: overlay 报文
        :param sport: 默认为0, 不关注源端口配置
        :param vrf_mac: 默认为空,如果设置了vrfmac需要指定
        :param ov_dst_mac: 默认为空,如果设置gateway, 需要指定该参数
        :return pkt
        """
        ntb_ov_src_mac = self.ntb_send_ov_smac
        ntb_ov_dst_mac = self.ntb_send_ov_dmac
        underlay = IPv6(dst=dip, src=sip, hlim=hlim)
        vxlanh = UDP(sport=sport, dport=4789, chksum=0) / VXLAN(vni=vni, flags="Instance") / Ether(
            src=ntb_ov_src_mac, dst=ntb_ov_dst_mac)
        return underlay / vxlanh / inner_frame

    def create_ipv6_gre_pkt(self, sip, dip, inner_frame, vpcid=12345678, hlim=64):
        """
        构造双层gre报文
        :param vpcid: vpcid值
        :param inner_frame: overlay 报文
        :return pkt
        """
        underlay = IPv6(dst=dip, src=sip, hlim=hlim)
        greh = GRE(key_present=1, key=vpcid)
        return underlay / greh / inner_frame

    def create_vlan_pkt(self, prio=0, id=0, vlan=1, type=0, payload=None):
        """
        构造overlay vlan 报文
        """
        pkt = Dot1Q(prio=prio, id=id, vlan=vlan, type=type)
        if payload:
            pkt = pkt / payload
        return pkt

    def create_udp_pkt(self, sip, dip, ttl=64, dscp=0, sport=1234, dport=5678,
                       pkt_len=100,df=0, payload=None):

        """
        构造ovelray udp报文
        :param sip: 源IP
        :param dip: 目的IP
        :param ttl: 可以不指定, 默认64
        :param sport: 可以不指定, 默认1234
        :param dport: 可以不指定, 默认5678
        :param pkt_len: 可以不指定, 默认100
        :param payload: 可以不指定, 默认None
        :return pkt
        """
        pkt = IP(dst=dip, src=sip, ttl=ttl,flags=df, tos=(dscp<<2)) / UDP(dport=dport, sport=sport)
        if payload:
            pkt = pkt / payload
        if (pkt_len - len(pkt)) > 0:
            pkt = pkt / codecs.decode("".join(["%02x" % (x % 256) for x in range(pkt_len - len(pkt))]), "hex")
        return pkt

    def create_tcp_pkt(self, sip, dip, ttl=64, dscp=0, sport=1234, dport=5678, flags=0, tcp_options="", ip_flags=0x0,
                       ip_frag=0x0,
                       pkt_len=100, payload=None):
        """
        构造ovelray tcp报文
        :param sip: 源IP
        :param dip: 目的IP
        :param ttl: 可以不指定, 默认64
        :param sport: 可以不指定, 默认1234
        :param dport: 可以不指定, 默认5678
        :param pkt_len: 可以不指定, 默认100
        :param payload: 可以不指定, 默认None
        :return pkt
        """
        pkt = IP(dst=dip, src=sip, ttl=ttl, flags=ip_flags, frag=ip_frag, tos=(dscp<<2)) / TCP(dport=dport, sport=sport,
                                                                                              flags=flags,
                                                                                              options=tcp_options)

        if payload:
            pkt = pkt / payload
        if (pkt_len - len(pkt)) > 0:
            pkt = pkt / codecs.decode("".join(["%02x" % (x % 256) for x in range(pkt_len - len(pkt))]), "hex")
        return pkt

    def create_icmp_pkt(self, sip, dip, ttl=64, icmp_type=8, icmp_code=0,
                        pkt_len=100, dscp=0, payload=None):
        """
        构造ovelray icmp报文
        :param sip: 源IP
        :param dip: 目的IP
        :param ttl: 可以不指定, 默认64
        :param icmp_type: 可以不指定, 默认icmp_echo
        :param icmp_code: 可以不指定, 默认icmp_echo
        :param pkt_len: 可以不指定, 默认100
        :param payload: 可以不指定, 默认None
        :return pkt
        """
        pkt = IP(dst=dip, src=sip, ttl=ttl, tos=(dscp<<2)) / ICMP(type=icmp_type, code=icmp_code)
        if payload:
            pkt = pkt / payload
        if (pkt_len - len(pkt)) > 0:
            pkt = pkt / codecs.decode("".join(["%02x" % (x % 256) for x in range(pkt_len - len(pkt))]), "hex")
        return pkt

    def create_ip_only_pkt(self, sip, dip, proto_id=0, dscp=0, ttl=64, pkt_len=100, options="", payload=None):
        """
        构造ovelray ip报文
        :param sip: 源IP
        :param dip: 目的IP
        :param ttl: 可以不指定, 默认64
        :param pkt_len: 可以不指定, 默认100
        :param payload: 可以不指定, 默认None
        :return pkt
        """
        pkt = IP(dst=dip, src=sip, ttl=ttl, options=options, proto=proto_id, tos=(dscp<<2))
        if payload:
            pkt = pkt / payload
        if (pkt_len - len(pkt)) > 0:
            pkt = pkt / codecs.decode("".join(["%02x" % (x % 256) for x in range(pkt_len - len(pkt))]), "hex")
        return pkt

    def create_arp_pkt(self,
                       eth_dst='ff:ff:ff:ff:ff:ff',
                       eth_src='00:06:07:08:09:0a',
                       arp_op=1,
                       ip_snd='192.168.0.1',
                       ip_tgt='192.168.0.2',
                       hw_snd='00:06:07:08:09:0a',
                       hw_tgt='00:00:00:00:00:00'):
        """
        构造arp报文
        :param len: Length of packet in bytes w/o CRC
        :param eth_dst: Destinatino MAC
        :param eth_src: Source MAC
        :param arp_op: Operation (1=request, 2=reply)
        :param ip_snd: Sender IP
        :param ip_tgt: Target IP
        :param hw_snd: Sender hardware address
        :param hw_tgt: Target hardware address 
        :return pkt
        """
        pkt = ARP(op=arp_op, hwsrc=hw_snd, psrc=ip_snd, hwdst=hw_tgt, pdst=ip_tgt)

        return pkt

    def ipv6_to_ns_multicast_mac(self, ipv6_address):
        ipv6 = ipaddress.IPv6Address(ipv6_address)
        last24bits = ipv6.packed[-3:]
        ns_multicast_mac = "33:33:ff:{:02x}:{:02x}:{:02x}".format(last24bits[0], last24bits[1], last24bits[2])
        return ns_multicast_mac

    def ipv6_to_solicited_node_multicast(self, ipv6_address):
        ipv6 = ipaddress.IPv6Address(ipv6_address)
        solicited_node_multicast = ipaddress.IPv6Address("ff02::1:ff00:0").packed[:-3] + ipv6.packed[-3:]
        return ipaddress.IPv6Address(solicited_node_multicast)

    def create_ipv6_udp_pkt(self, sip, dip, hlim=64, dscp=0, sport=1234, dport=5678, ip_len=None, udp_len=None,
                        pkt_len = 100, hbh_options=[], ext_headers=[], payload=None,chksum=None):
        """
        构造ovelray udp报文
        :param sip: 源IP
        :param dip: 目的IP
        :param hlim: 可以不指定, 默认64
        :param sport: 可以不指定, 默认1234
        :param dport: 可以不指定, 默认5678
        :param udp_len: sd
        :param pkt_len: 可以不指定, 默认100
        :param payload: 可以不指定, 默认None
        :param hbh_options: hop by hop option, eg: ["RouterAlert", "HAO", "Jumbo"] 
        :param ext_headers: 其他扩展头, eg: ["Routing", "Fragment", "Dest"]
        :return pkt
        """
        if ip_len is not None:
            ipv6_hrd = IPv6(dst=dip,src=sip,hlim=hlim, plen=1461,tc=dscp<<2) 
        else:
            ipv6_hrd = IPv6(dst=dip,src=sip,hlim=hlim,tc=dscp<<2) 
        if len(hbh_options) != 0:
            opt=[]
            for hbh_opt in hbh_options:
                if hbh_opt == "RouterAlert":
                    opt.append(RouterAlert())
                if hbh_opt == "HAO":
                    opt.append(HAO())
                if hbh_opt == "Jumbo":
                    opt.append(Jumbo())
            ipv6_hrd = ipv6_hrd/IPv6ExtHdrHopByHop(options=opt)
        if len(ext_headers) != 0:
            for ext_header in ext_headers:
                if ext_header == "Routing":
                    ipv6_hrd = ipv6_hrd/IPv6ExtHdrRouting()
                if ext_header == "Fragment":
                    ipv6_hrd = ipv6_hrd/IPv6ExtHdrFragment()
                if ext_header == "Dest":
                    ipv6_hrd = ipv6_hrd/IPv6ExtHdrDestOpt()
        if udp_len is not None and chksum is not None:
            pkt=ipv6_hrd/UDP(dport=dport,sport=sport, len=udp_len, chksum=chksum)
        elif udp_len is not None:
            pkt=ipv6_hrd/UDP(dport=dport,sport=sport, len=udp_len)
        elif chksum is not None:
            pkt=ipv6_hrd/UDP(dport=dport,sport=sport, chksum=chksum)  
        else:
            pkt=ipv6_hrd/UDP(dport=dport,sport=sport)
        if payload:
            pkt = pkt/payload
        if (pkt_len - len(pkt)) > 0:
            pkt = pkt/codecs.decode("".join(["%02x"%(x%256) for x in range(pkt_len - len(pkt))]), "hex")
        return pkt

    def create_ipv6_tcp_pkt(self, sip, dip, hlim=64, dscp=0, sport=1234, dport=5678, flags=0, tcp_options="",
                        pkt_len = 100, hbh_options=[], ext_headers=[], payload=None):
        """
        构造ovelray ipv6 tcp报文
        :param sip: 源IP
        :param dip: 目的IP
        :param hlim: 可以不指定, 默认64
        :param sport: 可以不指定, 默认1234
        :param dport: 可以不指定, 默认5678
        :param pkt_len: 可以不指定, 默认100
        :param payload: 可以不指定, 默认None
        :param hbh_options: hop by hop option, eg: ["RouterAlert", "HAO", "Jumbo"] 
        :param ext_headers: 其他扩展头, eg: ["Routing", "Fragment", "Dest"]
        :return pkt
        """
        ipv6_hrd = IPv6(dst=dip,src=sip,hlim=hlim,tc=dscp<<2) 
        if len(hbh_options) != 0:
            opt=[]
            for hbh_opt in hbh_options:
                if hbh_opt == "RouterAlert":
                    opt.append(RouterAlert())
                if hbh_opt == "HAO":
                    opt.append(HAO())
                if hbh_opt == "Jumbo":
                    opt.append(Jumbo())
            ipv6_hrd = ipv6_hrd/IPv6ExtHdrHopByHop(options=opt)
        if len(ext_headers) != 0:
            for ext_header in ext_headers:
                if ext_header == "Routing":
                    ipv6_hrd = ipv6_hrd/IPv6ExtHdrRouting()
                if ext_header == "Fragment":
                    ipv6_hrd = ipv6_hrd/IPv6ExtHdrFragment()
                if ext_header == "Dest":
                    ipv6_hrd = ipv6_hrd/IPv6ExtHdrDestOpt()
        pkt=ipv6_hrd/TCP(dport=dport,sport=sport,flags=flags, options=tcp_options)
        if payload:
            pkt = pkt/payload
        if (pkt_len - len(pkt)) > 0:
            pkt = pkt/codecs.decode("".join(["%02x"%(x%256) for x in range(pkt_len - len(pkt))]), "hex")
        return pkt

    def create_ipv6_icmp_pkt(self, sip, dip, hlim=64, dscp=0, icmp_type=128, icmp_code=0, ip_len=None,
                        pkt_len = 100, hbh_options=[], ext_headers=[], payload=None, mtu=1500):
        """
        构造ovelray ipv6 icmp报文
        :param sip: 源IP
        :param dip: 目的IP
        :param hlim: 可以不指定, 默认64
        :param sport: 可以不指定, 默认1234
        :param dport: 可以不指定, 默认5678
        :param pkt_len: 可以不指定, 默认100
        :param payload: 可以不指定, 默认None
        :param hbh_options: hop by hop option, eg: ["RouterAlert", "HAO", "Jumbo"] 
        :param ext_headers: 其他扩展头, eg: ["Routing", "Fragment", "Dest"]
        :return pkt
        """
        if ip_len is not None:
            ipv6_hrd = IPv6(dst=dip,src=sip,hlim=hlim, plen=ip_len,tc=dscp<<2)
        else:
            ipv6_hrd = IPv6(dst=dip,src=sip,hlim=hlim, tc=dscp<<2) 
        if len(hbh_options) != 0:
            opt=[]
            for hbh_opt in hbh_options:
                if hbh_opt == "RouterAlert":
                    opt.append(RouterAlert())
                if hbh_opt == "HAO":
                    opt.append(HAO())
                if hbh_opt == "Jumbo":
                    opt.append(Jumbo())
            ipv6_hrd = ipv6_hrd/IPv6ExtHdrHopByHop(options=opt)
        if len(ext_headers) != 0:
            for ext_header in ext_headers:
                if ext_header == "Routing":
                    ipv6_hrd = ipv6_hrd/IPv6ExtHdrRouting()
                if ext_header == "Fragment":
                    ipv6_hrd = ipv6_hrd/IPv6ExtHdrFragment()
                if ext_header == "Dest":
                    ipv6_hrd = ipv6_hrd/IPv6ExtHdrDestOpt()
        if icmp_type == 2:
            pkt=ipv6_hrd/ICMPv6PacketTooBig(mtu=mtu)
        elif icmp_type == 3:
            pkt=ipv6_hrd/ICMPv6TimeExceeded(code=icmp_code)
        else:
            pkt=ipv6_hrd/ICMPv6EchoRequest(type=icmp_type, code=icmp_code)
        if payload:
            pkt = pkt/payload
        if (pkt_len - len(pkt)) > 0:
            pkt = pkt/("0" * (pkt_len - len(pkt)))
        return pkt

    def create_ipv6_only_pkt(self, sip, dip, hlim=64, dscp=0, proto_id=255,
                        pkt_len = 100, payload=None, flow_label=0):
        """
        构造ovelray ipv6 only报文
        :param sip: 源IP
        :param dip: 目的IP
        :param hlim: 可以不指定, 默认64
        :param sport: 可以不指定, 默认1234
        :param dport: 可以不指定, 默认5678
        :param pkt_len: 可以不指定, 默认100
        :param payload: 可以不指定, 默认None
        :param hbh_options: hop by hop option, eg: ["RouterAlert", "HAO", "Jumbo"] 
        :param ext_headers: 其他扩展头, eg: ["Routing", "Fragment", "Dest"]
        :return pkt
        """
        pkt = IPv6(dst=dip,src=sip,hlim=hlim, nh=proto_id, fl=flow_label,tc=dscp<<2)
        if payload:
            pkt = pkt/payload
        if (pkt_len - len(pkt)) > 0:
            pkt = pkt/("0" * (pkt_len - len(pkt)))
        return pkt

    def create_ipv6_ns_pkt(self, sip, dip, tgt_ip, src_lladdr="00:11:22:33:44:55", hlim=64, encap_nd_opt=True,
                        hbh_options=[], pkt_len=0):
        """
        构造icmpv6 ns报文
        :param sip: 源IP
        :param dip: 目的IP
        :param hlim: 可以不指定, 默认64
        :param sport: 可以不指定, 默认1234
        :param dport: 可以不指定, 默认5678
        :param pkt_len: 可以不指定, 默认100
        :param payload: 可以不指定, 默认None
        :param hbh_options: hop by hop option, eg: ["RouterAlert", "HAO", "Jumbo"] 
        :param ext_headers: 其他扩展头, eg: ["Routing", "Fragment", "Dest"]
        :return pkt
        """
        ipv6_hrd = IPv6(dst=dip,src=sip,hlim=hlim) 
        if len(hbh_options) != 0:
            opt=[]
            for hbh_opt in hbh_options:
                if hbh_opt == "RouterAlert":
                    opt.append(RouterAlert())
                if hbh_opt == "HAO":
                    opt.append(HAO())
                if hbh_opt == "Jumbo":
                    opt.append(Jumbo())
            ipv6_hrd = ipv6_hrd/IPv6ExtHdrHopByHop(options=opt)
        ns = ICMPv6ND_NS(tgt=tgt_ip)
        if encap_nd_opt:
            opt = ICMPv6NDOptSrcLLAddr(lladdr=src_lladdr)
            pkt=ipv6_hrd/ns/opt
        else:
            pkt=ipv6_hrd/ns

        if (pkt_len - len(pkt)) > 0:
            pkt = pkt/("0" * (pkt_len - len(pkt)))
        return pkt

    def create_ipv6_na_pkt(self, sip, dip, tgt_ip, tgt_lladr="00:11:22:33:44:55", hlim=64, overrride_flag=0, encap_nd_opt=True,
                        hbh_options=[], pkt_len=0, solicitation_flag=1):
        """
        构造icmpv6 na报文
        :param sip: 源IP
        :param dip: 目的IP
        :param hlim: 可以不指定, 默认64
        :param sport: 可以不指定, 默认1234
        :param dport: 可以不指定, 默认5678
        :param pkt_len: 可以不指定, 默认100
        :param payload: 可以不指定, 默认None
        :param hbh_options: hop by hop option, eg: ["RouterAlert", "HAO", "Jumbo"] 
        :param ext_headers: 其他扩展头, eg: ["Routing", "Fragment", "Dest"]
        :return pkt
        """
        ipv6_hrd = IPv6(dst=dip,src=sip,hlim=hlim) 
        if len(hbh_options) != 0:
            opt=[]
            for hbh_opt in hbh_options:
                if hbh_opt == "RouterAlert":
                    opt.append(RouterAlert())
                if hbh_opt == "HAO":
                    opt.append(HAO())
                if hbh_opt == "Jumbo":
                    opt.append(Jumbo())
            ipv6_hrd = ipv6_hrd/IPv6ExtHdrHopByHop(options=opt)

        na = ICMPv6ND_NA(tgt=tgt_ip, R=0, S=solicitation_flag, O=overrride_flag)
        if encap_nd_opt:
            opt = ICMPv6NDOptDstLLAddr(lladdr=tgt_lladr)
            pkt=ipv6_hrd/na/opt
        else:
            pkt=ipv6_hrd/na
            
        if (pkt_len - len(pkt)) > 0:
            pkt = pkt/codecs.decode("".join(["%02x"%(x%256) for x in range(pkt_len - len(pkt))]), "hex")
        return pkt

    def send_pkt(self, pkt, count=1):
        """
        调用PTF发送报文
        :param pkt: 要发送的报文
        :param count: 要发送的报文个数
        :return:
        """
        testutils.send_packet(self, (0, 0), pkt, count)

    def send_pkt_delay(self, pkt, count=1, port_id=(0, 0), delay=1):
        """
        调用PTF发送报文
        :param pkt: 要发送的报文
        :param count: 要发送的报文个数
        :return:
        """
        send_thread = MyThread(testutils.send_packet, args=(self, port_id, pkt, count), delay=delay)
        send_thread.start()
        # testutils.send_packet(self, port_id, pkt, count)

    def verify_packet(self, exp_pkt, ignore_sip=True, ignore_sport=True, ignore_l4len=False):
        """
        验证回包是否是预期报文
        :param exp_pkt: 预期报文
        :param ignore_sip: 是否忽略underlay 源IP
        :param ignore_sport: 是否忽略underlay 源端口
        :return:
        """
        is_udp_or_tcp = False
        if isinstance(exp_pkt, Ether):
            l3 = exp_pkt.payload
            if isinstance(l3, IP):
                proto = l3.proto
                if proto == 17 or proto == 6:
                    is_udp_or_tcp = True
        m = Mask(exp_pkt)
        m.set_do_not_care_scapy(IP, 'id')
        m.set_do_not_care_scapy(IP, 'chksum')
        m.set_do_not_care_scapy(IP, 'ttl')
        m.set_do_not_care_scapy(IP, 'tos')
        if ignore_sip:
            m.set_do_not_care_scapy(IP, 'src')
        if ignore_sport and is_udp_or_tcp:
            m.set_do_not_care_scapy(UDP, 'sport')
        if ignore_l4len:
            m.set_do_not_care_scapy(UDP, 'len')
        testutils.verify_packet(self, m, port_id=(0, 0), timeout=4)

    def verify_packet_underlay(self, exp_pkt, ignore_sip=True, ignore_sport=True, ignore_l4len=False):
        """
        验证回包是否是预期报文
        :param exp_pkt: 预期报文
        :param ignore_sip: 是否忽略underlay 源IP
        :param ignore_sport: 是否忽略underlay 源端口
        :return:
        """
        is_udp_or_tcp = False
        if isinstance(exp_pkt, Ether):
            l3 = exp_pkt.payload
            if isinstance(l3, IP):
                proto = l3.proto
                if proto == 17 or proto == 6:
                    is_udp_or_tcp = True
        m = Mask(exp_pkt)
        m.set_do_not_care_scapy(IP, 'id')
        # m.set_do_not_care_scapy(IP, 'chksum')
        m.set_do_not_care_scapy(IP, 'ttl')
        # m.set_do_not_care_scapy(IP, 'tos')
        # if ignore_sip:
        #     m.set_do_not_care_scapy(IP, 'src')
        # if ignore_sport and is_udp_or_tcp:
        #     m.set_do_not_care_scapy(UDP, 'sport')
        # if ignore_l4len:
        #     m.set_do_not_care_scapy(UDP, 'len')
        testutils.verify_packet(self, m, port_id=(0, 0), timeout=4)

    def verify_no_packet(self, exp_pkt, ignore_sip=True, ignore_sport=True):
        """
        验证没有收到指定报文
        :param exp_pkt: 预期报文
        :param ignore_sip: 是否忽略underlay 源IP
        :param ignore_sport: 是否忽略underlay 源端口
        :return:
        """
        is_udp_or_tcp = False
        if isinstance(exp_pkt, Ether):
            l3 = exp_pkt.payload
            if isinstance(l3, IP):
                proto = l3.proto
                if proto == 17 or proto == 6:
                    is_udp_or_tcp = True
        m = Mask(exp_pkt)
        m.set_do_not_care_scapy(IP, 'id')
        m.set_do_not_care_scapy(IP, 'chksum')
        m.set_do_not_care_scapy(IP, 'ttl')
        m.set_do_not_care_scapy(IP, 'tos')
        if ignore_sip:
            m.set_do_not_care_scapy(IP, 'src')
        if ignore_sport and is_udp_or_tcp:
            m.set_do_not_care_scapy(UDP, 'sport')
        testutils.verify_no_packet(self, m, port_id=(0, 0), timeout=4)

    def verify_packet_list(self, pkt_ll, ignore_sport=True, ignore_sip=True, poll_time=3):
        """
        Check that the packet_list in pkt_ll is received on the corresponding port_list in port_ll 
        belonging to the given device (default device_number is 0).
        :param port_ll: 端口list 的 list
        :param pkt_ll: 期待数据包list 的list
        :param poll_times: 抓包次数
        :param ignore_sport: 是否忽略underlay 源端口
        :return:
        """
        is_udp_or_tcp = False
        m_pkt_ll = []
        exp_port_ll = []
        for pkt_list in pkt_ll:
            m_pkt_list = []
            exp_port_list = []
            for exp_pkt in pkt_list:
                if isinstance(exp_pkt, Ether):
                    l3 = exp_pkt.payload
                    if isinstance(l3, IP):
                        proto = l3.proto
                        if proto == 17 or proto == 6:
                            is_udp_or_tcp = True
                m = Mask(exp_pkt)
                m.set_do_not_care_scapy(IP, 'id')
                m.set_do_not_care_scapy(IP, 'chksum')
                m.set_do_not_care_scapy(IP, 'ttl')
                m.set_do_not_care_scapy(IP, 'tos')
                if ignore_sip:
                    m.set_do_not_care_scapy(IP, 'src')
                if ignore_sport and is_udp_or_tcp:
                    m.set_do_not_care_scapy(UDP, 'sport')
                m_pkt_list.append(m)
                exp_port_list.append(0)
            m_pkt_ll.append(m_pkt_list)
            exp_port_ll.append(exp_port_list)

        testutils.verify_packet_list_new(self, exp_port_ll, m_pkt_ll, poll_time)

    def set_expect_packet_mask(self, exp_pkt, ignore_sip=True, ignore_sport=True, ignore_l4len=False, ignore_vni=False, ignore_vpcid=False):
        """
        验证回包是否是预期报文
        :param exp_pkt: 预期报文
        :param ignore_sip: 是否忽略underlay 源IP
        :param ignore_sport: 是否忽略underlay 源端口
        :param ignore_vni: 是否忽略vni
        :param ignore_vpcid: 是否忽略vpcid
        :return:
        """
        is_udp_or_tcp = False
        is_vxlan = False
        is_gre   = False
        if isinstance(exp_pkt, Ether):
            l3 = exp_pkt.payload
            if isinstance(l3, IP):
                proto = l3.proto
                if proto == 17 or proto == 6:
                    is_udp_or_tcp = True

        if VXLAN in exp_pkt:
            is_vxlan = True

        if GRE in exp_pkt:
            is_gre = True

        m = Mask(exp_pkt)
        m.set_do_not_care_scapy(IP, 'id')
        m.set_do_not_care_scapy(IP, 'chksum')
        m.set_do_not_care_scapy(IP, 'ttl')
        m.set_do_not_care_scapy(IP, 'tos')
        if ignore_sip:
            m.set_do_not_care_scapy(IP, 'src')
        if ignore_sport and is_udp_or_tcp:
            m.set_do_not_care_scapy(UDP, 'sport')
        if ignore_l4len:
            m.set_do_not_care_scapy(UDP, 'len')

        if ignore_vni and is_vxlan:
            m.set_do_not_care_scapy(VXLAN, 'vni')

        if ignore_vpcid and is_gre:
            m.set_do_not_care_scapy(GRE, 'key')
        return m

    def verify_packet_and_return_pkt(self, exp_pkt, timeout=4):
        """
        验证回包是否是预期报文
        :param exp_pkt: 预期报文
        :param timeout: 超时时间
        :return:
        """
        result = testutils.verify_packet_and_return_result(self, exp_pkt, port_id=(0, 0), timeout=4)
        if result is None:
            return

        ret_pkt = Ether(result.packet)
        return ret_pkt

    def verify_packet_quick(self, exp_pkt, timeout=4):
        """
        验证回包是否是预期报文
        :param exp_pkt: 预期报文
        :param timeout: 超时时间
        """
        result = testutils.verify_packet(self, exp_pkt, port_id=(0, 0), timeout=timeout)
    
    def send_and_verify_packet_quick(self, send_pkt, exp_pkt, timeout=4):
        exp_pkt = self.set_expect_packet_mask(exp_pkt)
        self.send_pkt(send_pkt)
        self.verify_packet_quick(exp_pkt, timeout=timeout)

    def verify_packet_in_packet_list(self, exp_pkt_list=[], ignore_sport=True, ignore_sip=True, timeout=4):
        """
        验证回包是否在预期报文list中
        :param exp_pkt_list: 预期报文集合
        :return: ret_pkt
        """
        m_pkt_list = []
        for exp_pkt in exp_pkt_list:
            is_udp_or_tcp = False
            if isinstance(exp_pkt, Ether):
                l3 = exp_pkt.payload
                if isinstance(l3, IP):
                    proto = l3.proto
                    if proto == 17 or proto == 6:
                        is_udp_or_tcp = True
            m = Mask(exp_pkt)
            m.set_do_not_care_scapy(IP, 'id')
            m.set_do_not_care_scapy(IP, 'chksum')
            m.set_do_not_care_scapy(IP, 'ttl')
            m.set_do_not_care_scapy(IP, 'tos')
            if ignore_sip:
                m.set_do_not_care_scapy(IP, 'src')
            if ignore_sport and is_udp_or_tcp:
                m.set_do_not_care_scapy(UDP, 'sport')
            m_pkt_list.append(m)

        result = testutils.verify_any_packet_any_port_and_return_result(self, m_pkt_list)
        return result

    # ******************************************思博伦测试仪*******************************************************#
    def spirent_hello(self):
        """
        spirent hello test
        :param:
        :return:
        """
        dict_request = {
        }

        grpc_ret = self.spirent_grpc_client.grpc_call("hello", dict_request)
        self.assert_("spirent hello faild", grpc_ret["info"] == "success")

    def spirent_create_instance(self):
        """
        创建思博伦测试仪实例
        :return:
            instance_name: 新创建的实例名称
        """
        dict_request = {
        }

        grpc_ret = self.spirent_grpc_client.grpc_call("createInstance", dict_request)
        self.assert_("spirent create instance faild", grpc_ret["result"]["info"] == "success")
        return grpc_ret["instance_name"]

    def spirent_delete_instance(self):
        """
        删除思博伦测试仪实例
        :param:
        :return:
        """
        dict_request = {
            "instance_name": self.instance_name
        }

        grpc_ret = self.spirent_grpc_client.grpc_call("deleteInstance", dict_request)
        self.assert_("spirent delete instance faild", grpc_ret["info"] == "success")

    def spirent_init(self, chassip):
        """
        思博伦测试仪初始化
        :param chassip: 测试仪chassip
        :return:
        """
        dict_request = {
            "instance_name": self.instance_name,
            "chassip": chassip
        }

        grpc_ret = self.spirent_grpc_client.grpc_call("init", dict_request)
        self.assert_("spirent init faild", grpc_ret["info"] == "success")

    def spirent_load_tcc_file(self, tcc_file):
        """
        思博伦测试仪加载tcc文件
        :param tcc_file: 指定在grpc服务所在设备的路径 
        :return:
        """
        dict_request = {
            "instance_name": self.instance_name,
            "tcc_file": tcc_file
        }

        grpc_ret = self.spirent_grpc_client.grpc_call("loadTccFile", dict_request)
        self.assert_("spirent load tcc file faild", grpc_ret["info"] == "success")

    def spirent_create_port(self, port_index):
        """
        创建思博伦测试仪端口
        :param port_index: 测试仪端口索引，例如 1/37
        :return:
        """
        dict_request = {
            "instance_name": self.instance_name,
            "port_index": port_index
        }

        grpc_ret = self.spirent_grpc_client.grpc_call("createPort", dict_request)
        self.assert_("spirent create port faild", grpc_ret["info"] == "success")

    def spirent_delete_port(self, port_index):
        """
        删除思博伦测试仪端口
        :param port_index: 测试仪端口索引，例如 1/37
        :return:
        """
        dict_request = {
            "instance_name": self.instance_name,
            "port_index": port_index
        }

        grpc_ret = self.spirent_grpc_client.grpc_call("deletePort", dict_request)
        self.assert_("spirent delete port faild", grpc_ret["info"] == "success")

    def spirent_attach_port(self, port_index):
        """
        占用并连接思博伦测试仪端口
        :param port_index: 测试仪端口索引，例如 1/37
        :return:
        """
        dict_request = {
            "instance_name": self.instance_name,
            "port_index": port_index
        }

        grpc_ret = self.spirent_grpc_client.grpc_call("attachPort", dict_request)
        self.assert_("spirent attach port faild", grpc_ret["info"] == "success")

    def spirent_detach_port(self, port_index):
        """
        断开思博伦测试仪端口
        :param port_index: 测试仪端口索引，例如 1/37
        :return:
        """
        dict_request = {
            "instance_name": self.instance_name,
            "port_index": port_index
        }

        grpc_ret = self.spirent_grpc_client.grpc_call("detachPort", dict_request)
        self.assert_("spirent detach port faild", grpc_ret["info"] == "success")

    def spirent_create_l3_device(self, port_index, dev_name, local_ip, peer_ip):
        """
        创建思博伦测试仪虚拟三层口
        :param port_index: 测试仪端口索引，例如 1/37
        :param dev_name: 三层设备名称
        :param local_ip: 三层设备本地IP地址
        :param peer_ip:  三层设备对端IP地址
        :return:
        """
        dict_request = {
            "instance_name": self.instance_name,
            "port_index": port_index,
            "dev_name": dev_name,
            "local_ip": local_ip,
            "peer_ip": peer_ip,
        }

        grpc_ret = self.spirent_grpc_client.grpc_call("createDevice", dict_request)
        self.assert_("spirent create l3 device faild", grpc_ret["info"] == "success")

    def spirent_create_vlan_device(self, port_index, dev_name, local_ip, peer_ip, vlan_id):
        """
        创建思博伦测试仪虚拟vlanif
        :param port_index: 测试仪端口索引，例如 1/37
        :param dev_name: vlan设备名称
        :param local_ip: vlan设备本地IP地址
        :param peer_ip:  vlan设备对端IP地址
        :param vlan_id:  vlan id
        :return:
        """
        dict_request = {
            "instance_name": self.instance_name,
            "port_index": port_index,
            "dev_name": dev_name,
            "local_ip": local_ip,
            "peer_ip": peer_ip,
            "vlan_id": vlan_id
        }

        grpc_ret = self.spirent_grpc_client.grpc_call("createVlanDevice", dict_request)
        self.assert_("spirent create vlan device faild", grpc_ret["info"] == "success")

    def spirent_config_generator(self, port_index, mode, pkt_num, load, load_unit):
        """
        配置思博伦测试仪流生成器
        :param port_index: 测试仪端口索引，例如 1/37
        :param mode: 打流模式, 支持 ”BURSTS“ 和 ”CONTINUOUS“
        :param pkt_num: 报文个数, 如果为”CONTINUOUS“, 设置为0即可
        :param load:  负载大小, 如果load_unit = PERCENT_LINE_RATE, 则load取值1~100; 如果FRAMES_PER_SECOND, 则load表示pps的值
        :param load_unit: 负载单位, 支持PERCENT_LINE_RATE/FRAMES_PER_SECOND
        :return:
        """
        dict_request = {
            "instance_name": self.instance_name,
            "port_index": port_index,
            "mode": mode,
            "pkt_num": pkt_num,
            "load": load,
            "load_unit": load_unit
        }

        grpc_ret = self.spirent_grpc_client.grpc_call("configGenerator", dict_request)
        self.assert_("spirent config generator faild", grpc_ret["info"] == "success")

    def spirent_config_burst_generator(self, port_index, pkt_num, load="0.1", load_unit="PERCENT_LINE_RATE"):
        """
        配置思博伦测试仪burst流生成器
        :param port_index: 测试仪端口索引，例如 1/37
        :param pkt_num: 报文个数, 如果为”CONTINUOUS“, 设置为0即可
        :param load:  负载大小, 如果load_unit = PERCENT_LINE_RATE, 则load取值1~100; 如果FRAMES_PER_SECOND, 则load表示pps的值
        :param load_unit: 负载单位, 支持PERCENT_LINE_RATE/FRAMES_PER_SECOND
        :return:
        """
        self.spirent_config_generator(port_index, "BURSTS", pkt_num, load, load_unit)

    def spirent_config_continue_generator(self, port_index, load, load_unit="PERCENT_LINE_RATE"):
        """
        配置思博伦测试仪CONTINUOUS流生成器
        :param port_index: 测试仪端口索引，例如 1/37
        :param load:  负载大小, 如果load_unit = PERCENT_LINE_RATE, 则load取值1~100; 如果FRAMES_PER_SECOND, 则load表示pps的值
        :param load_unit: 负载单位, 支持PERCENT_LINE_RATE/FRAMES_PER_SECOND
        :return:
        """
        self.spirent_config_generator(port_index, "CONTINUOUS", 0, load, load_unit)

    def spirent_start_nd_arp(self, port_index):
        """
        设置物理端口下的所有虚拟口请求arp
        :param port_index: 测试仪端口索引，例如 1/37
        :return:
        """
        dict_request = {
            "instance_name": self.instance_name,
            "port_index": port_index
        }

        grpc_ret = self.spirent_grpc_client.grpc_call("startNdArp", dict_request)
        self.assert_("spirent start nd arp faild", grpc_ret["info"] == "success")

    def spirent_start_traffic(self, port_index):
        """
        启动思博伦测试仪打流
        :param port_index: 测试仪端口索引，例如 1/37
        :return:
        """
        dict_request = {
            "instance_name": self.instance_name,
            "port_index": port_index
        }

        grpc_ret = self.spirent_grpc_client.grpc_call("startTraffic", dict_request)
        self.assert_("spirent start traffic faild", grpc_ret["info"] == "success")

    def spirent_stop_traffic(self, port_index):
        """
        停止思博伦测试仪打流
        :param port_index: 测试仪端口索引，例如 1/37
        :return:
        """
        dict_request = {
            "instance_name": self.instance_name,
            "port_index": port_index
        }

        grpc_ret = self.spirent_grpc_client.grpc_call("stopTraffic", dict_request)
        self.assert_("spirent stop traffic faild", grpc_ret["info"] == "success")

    def spirent_check_traffic_completed(self, port_index):
        """
        检查思博伦测试仪打流是否完成
        :param port_index: 测试仪端口索引，例如 1/37
        :return:
            is_complete: bool
        """
        dict_request = {
            "instance_name": self.instance_name,
            "port_index": port_index
        }

        grpc_ret = self.spirent_grpc_client.grpc_call("checkTrafficComplete", dict_request)
        self.assert_("spirent check traffic completed faild", grpc_ret["result"]["info"] == "success")
        return grpc_ret["is_complete"]

    def spirent_wait_traffic_complete(self, port_index):
        while True:
            is_complete = self.spirent_check_traffic_completed(port_index)
            if is_complete:
                break
            time.sleep(1)

    def spirent_get_port_stat(self, port_index):
        """
        获取思博伦测试仪端口统计
        :param port_index: 测试仪端口索引，例如 1/37
        :return:
            (rx_pkts, tx_pkts)
        """
        dict_request = {
            "instance_name": self.instance_name,
            "port_index": port_index
        }

        grpc_ret = self.spirent_grpc_client.grpc_call("getPortStat", dict_request)
        self.assert_("spirent get port stat faild", grpc_ret["result"]["info"] == "success")
        return grpc_ret["stat"]["tx_pkts"], grpc_ret["stat"]["rx_pkts"]

    def spirent_get_stream_stat(self, port_index, stream_name):
        """
        获取基于流的收发包统计
        :param port_index: 测试仪端口索引，例如 1/37
        :param stream_name: 流量名
        :return:
            (rx_pkts, tx_pkts)
        """
        dict_request = {
            "instance_name": self.instance_name,
            "port_index": port_index,
            "stream_name": stream_name
        }

        grpc_ret = self.spirent_grpc_client.grpc_call("getStreamStat", dict_request)
        self.assert_("spirent get stream stat faild", grpc_ret["result"]["info"] == "success")
        return grpc_ret["stat"]["tx_pkts"], grpc_ret["stat"]["rx_pkts"]

    def spirent_start_2544_task(self):
        """
        启动思博伦测试仪2544任务
        :param:
        :return:
        """
        dict_request = {
            "instance_name": self.instance_name,
        }

        grpc_ret = self.spirent_grpc_client.grpc_call("start2544Task", dict_request)
        self.assert_("spirent start 2544 task faild", grpc_ret["info"] == "success")

    def spirent_check_2544_task_completed(self):
        """
        检查思博伦2544任务是否完成
        :param:
        :return:
        """
        dict_request = {
            "instance_name": self.instance_name,
        }

        grpc_ret = self.spirent_grpc_client.grpc_call("check2544TaskComplete", dict_request)
        self.assert_("spirent check 2544 task completed faild", grpc_ret["result"]["info"] == "success")
        return grpc_ret["is_complete"]

    def spirent_wait_2544_task_completed(self):
        """
        等待2544任务完成
        :param:
        :return:
        """
        while True:
            is_complete = self.spirent_check_2544_task_completed()
            if is_complete:
                break
            time.sleep(5)

    def spirent_get_2544_task_result(self):
        """
        获取思博伦2544任务执行结果
        :param:
        :return:
        """
        dict_request = {
            "instance_name": self.instance_name,
        }

        grpc_ret = self.spirent_grpc_client.grpc_call("get2544Result", dict_request)
        self.assert_("spirent get 2544 task result faild", grpc_ret["result"]["info"] == "success")
        return grpc_ret["throughput_results"]

    def spirent_create_stream(self, port_index, stream_name, min_frame_len=1200, max_frame_len=1200):
        """
        思博伦测试仪创建测试流量
        :param port_index: 测试仪端口索引，例如 1/37
        :param stream_name: 测试流名称, 同一个端口的多条流名称不能相同
        :return:
        """
        dict_request = {
            "instance_name": self.instance_name,
            "port_index": port_index,
            "stream_name": stream_name,
            "min_frame_len": min_frame_len,
            "max_frame_len": max_frame_len
        }

        grpc_ret = self.spirent_grpc_client.grpc_call("createStream", dict_request)
        self.assert_("spirent create stream faild", grpc_ret["info"] == "success")

    def spirent_active_stream(self, port_index, stream_name):
        """
        激活思博伦测试仪流量
        :param port_index: 测试仪端口索引，例如 1/37
        :param stream_name: 测试流名称, 同一个端口的多条流名称不能相同
        :return:
        """
        dict_request = {
            "instance_name": self.instance_name,
            "port_index": port_index,
            "stream_name": stream_name
        }

        grpc_ret = self.spirent_grpc_client.grpc_call("activeStream", dict_request)
        self.assert_("spirent active stream faild", grpc_ret["info"] == "success")

    def spirent_deactive_stream(self, port_index, stream_name):
        """
        deactive 思博伦测试仪流量
        :param port_index: 测试仪端口索引，例如 1/37
        :param stream_name: 测试流名称, 同一个端口的多条流名称不能相同
        :return:
        """
        dict_request = {
            "instance_name": self.instance_name,
            "port_index": port_index,
            "stream_name": stream_name
        }

        grpc_ret = self.spirent_grpc_client.grpc_call("deactiveStream", dict_request)
        self.assert_("spirent deactive stream faild", grpc_ret["info"] == "success")

    def spirent_push_ethhdr(self, port_index, stream_name, hdr_name, src_mac, dst_mac):
        """
        给指定流追加二层头
        :param port_index: 测试仪端口索引，例如 1/37
        :param stream_name: 测试流名称, 同一个端口的多条流名称不能相同
        :param hdr_name: 报文头名称, 用来设置range modifier时, 指定offset 
        :param src_mac: 源mac地址 
        :param dst_mac: 目的mac地址 
        :return:
        """
        dict_request = {
            "instance_name": self.instance_name,
            "port_index": port_index,
            "stream_name": stream_name,
            "hdr_name": hdr_name,
            "src_mac": src_mac,
            "dst_mac": dst_mac
        }

        grpc_ret = self.spirent_grpc_client.grpc_call("pushEthHdr", dict_request)
        self.assert_("spirent push eth hdr faild", grpc_ret["info"] == "success")

    def spirent_push_iphdr(self, port_index, stream_name, hdr_name, src_ip, dst_ip):
        """
        给指定流追加IP头
        :param port_index: 测试仪端口索引，例如 1/37
        :param stream_name: 测试流名称, 同一个端口的多条流名称不能相同
        :param hdr_name: 报文头名称, 用来设置range modifier时, 指定offset 
        :param src_ip: 源ip地址 
        :param dst_ip: 目的ip地址 
        :return:
        """
        dict_request = {
            "instance_name": self.instance_name,
            "port_index": port_index,
            "stream_name": stream_name,
            "hdr_name": hdr_name,
            "src_ip": src_ip,
            "dst_ip": dst_ip
        }

        grpc_ret = self.spirent_grpc_client.grpc_call("pushIpHdr", dict_request)
        self.assert_("spirent push ip hdr faild", grpc_ret["info"] == "success")

    def spirent_push_ipv6hdr(self, port_index, stream_name, hdr_name, src_ip, dst_ip):
        """
        给指定流追加IPv6头
        :param port_index: 测试仪端口索引，例如 1/37
        :param stream_name: 测试流名称, 同一个端口的多条流名称不能相同
        :param hdr_name: 报文头名称, 用来设置range modifier时, 指定offset 
        :param src_ip: 源ip地址 
        :param dst_ip: 目的ip地址 
        :return:
        """
        dict_request = {
            "instance_name": self.instance_name,
            "port_index": port_index,
            "stream_name": stream_name,
            "hdr_name": hdr_name,
            "src_ip": src_ip,
            "dst_ip": dst_ip
        }

        grpc_ret = self.spirent_grpc_client.grpc_call("pushIpv6Hdr", dict_request)
        self.assert_("spirent push ipv6 hdr faild", grpc_ret["info"] == "success")

    def spirent_push_ipv6_nshdr(self, port_index, stream_name, hdr_name, tgt_ipv6, encap_nd_opt, src_lladdr):
        """
        给指定流追加IPv6 NS头
        :param port_index: 测试仪端口索引，例如 1/37
        :param stream_name: 测试流名称, 同一个端口的多条流名称不能相同
        :param hdr_name: 报文头名称, 用来设置range modifier时, 指定offset 
        :param tgt_ipv6: 请求的目标IP地址
        :param encap_nd_opt: 是否封装option, bool类型
        :param src_lladdr: 只有encap_nd_opt为True时有效,表示源端mac地址
        :return:
        """
        dict_request = {
            "instance_name": self.instance_name,
            "port_index": port_index,
            "stream_name": stream_name,
            "hdr_name": hdr_name,
            "tgt_ipv6": tgt_ipv6,
            "encap_nd_opt": encap_nd_opt,
            "src_lladdr": src_lladdr
        }

        grpc_ret = self.spirent_grpc_client.grpc_call("pushIpv6NsHdr", dict_request)
        self.assert_("spirent push ipv6 ns hdr faild", grpc_ret["info"] == "success")

    def spirent_push_ipv6_nahdr(self, port_index, stream_name, hdr_name, tgt_ipv6, encap_nd_opt, tgt_lladdr):
        """
        给指定流追加IPv6 NA头
        :param port_index: 测试仪端口索引，例如 1/37
        :param stream_name: 测试流名称, 同一个端口的多条流名称不能相同
        :param hdr_name: 报文头名称, 用来设置range modifier时, 指定offset 
        :param tgt_ipv6: 请求的目标IP地址
        :param encap_nd_opt: 是否封装option, bool类型
        :param tgt_lladdr: 只有encap_nd_opt为True时有效,表示目标mac地址
        :return:
        """
        dict_request = {
            "instance_name": self.instance_name,
            "port_index": port_index,
            "stream_name": stream_name,
            "hdr_name": hdr_name,
            "tgt_ipv6": tgt_ipv6,
            "encap_nd_opt": encap_nd_opt,
            "tgt_lladdr": tgt_lladdr
        }

        grpc_ret = self.spirent_grpc_client.grpc_call("pushIpv6NaHdr", dict_request)
        self.assert_("spirent push ipv6 na hdr faild", grpc_ret["info"] == "success")

    def spirent_push_udphdr(self, port_index, stream_name, hdr_name, src_port, dst_port):
        """
        给指定流追加udp头
        :param port_index: 测试仪端口索引，例如 1/37
        :param stream_name: 测试流名称, 同一个端口的多条流名称不能相同
        :param hdr_name: 报文头名称, 用来设置range modifier时, 指定offset 
        :param src_port: 源端口号
        :param dst_port: 目的端口号
        :return:
        """
        dict_request = {
            "instance_name": self.instance_name,
            "port_index": port_index,
            "stream_name": stream_name,
            "hdr_name": hdr_name,
            "src_port": src_port,
            "dst_port": dst_port
        }

        grpc_ret = self.spirent_grpc_client.grpc_call("pushUpdHdr", dict_request)
        self.assert_("spirent push udp hdr faild", grpc_ret["info"] == "success")

    def spirent_push_tcphdr(self, port_index, stream_name, hdr_name, src_port, dst_port):
        """
        给指定流追加tcp头
        :param port_index: 测试仪端口索引，例如 1/37
        :param stream_name: 测试流名称, 同一个端口的多条流名称不能相同
        :param hdr_name: 报文头名称, 用来设置range modifier时, 指定offset 
        :param src_port: 源端口号
        :param dst_port: 目的端口号
        :return:
        """
        dict_request = {
            "instance_name": self.instance_name,
            "port_index": port_index,
            "stream_name": stream_name,
            "hdr_name": hdr_name,
            "src_port": src_port,
            "dst_port": dst_port
        }

        grpc_ret = self.spirent_grpc_client.grpc_call("pushTcpHdr", dict_request)
        self.assert_("spirent push tcp hdr faild", grpc_ret["info"] == "success")

    def spirent_push_vxlanhdr(self, port_index, stream_name, hdr_name, vni):
        """
        给指定流追加vxlan头
        :param port_index: 测试仪端口索引，例如 1/37
        :param stream_name: 测试流名称, 同一个端口的多条流名称不能相同
        :param hdr_name: 报文头名称, 用来设置range modifier时, 指定offset 
        :param vni: vni 值
        """
        dict_request = {
            "instance_name": self.instance_name,
            "port_index": port_index,
            "stream_name": stream_name,
            "hdr_name": hdr_name,
            "vni": vni,
        }

        grpc_ret = self.spirent_grpc_client.grpc_call("pushVxlanHdr", dict_request)
        self.assert_("spirent push vxlan hdr faild", grpc_ret["info"] == "success")

    def spirent_push_grehdr(self, port_index, stream_name, hdr_name, vpcid):
        """
        给指定流追加gre头
        :param port_index: 测试仪端口索引，例如 1/37
        :param stream_name: 测试流名称, 同一个端口的多条流名称不能相同
        :param hdr_name: 报文头名称, 用来设置range modifier时, 指定offset 
        :param vpcid: vpcid
        """
        dict_request = {
            "instance_name": self.instance_name,
            "port_index": port_index,
            "stream_name": stream_name,
            "hdr_name": hdr_name,
            "vpcid": vpcid,
        }

        grpc_ret = self.spirent_grpc_client.grpc_call("pushGreHdr", dict_request)
        self.assert_("spirent push gre hdr faild", grpc_ret["info"] == "success")

    def spirent_push_arphdr(self, port_index, stream_name, hdr_name,
                            sender_hwaddr, target_hwaddr, sender_ipaddr, target_ipaddr):
        """
        给指定流追加arp头
        :param port_index: 测试仪端口索引，例如 1/37
        :param stream_name: 测试流名称, 同一个端口的多条流名称不能相同
        :param hdr_name: 报文头名称, 用来设置range modifier时, 指定offset 
        :param sender_hwaddr: 发送端的mac地址
        :param target_hwaddr: 目的端的mac地址
        :param sender_ipaddr: 发送端的ip地址
        :param target_ipaddr: 目的端的ip地址
        """
        dict_request = {
            "instance_name": self.instance_name,
            "port_index": port_index,
            "stream_name": stream_name,
            "hdr_name": hdr_name,
            "sender_hwaddr": sender_hwaddr,
            "target_hwaddr": target_hwaddr,
            "sender_ipaddr": sender_ipaddr,
            "target_ipaddr": target_ipaddr,
        }

        grpc_ret = self.spirent_grpc_client.grpc_call("pushArpHdr", dict_request)
        self.assert_("spirent push arp hdr faild", grpc_ret["info"] == "success")

    def spirent_push_range_modifier(self, port_index, stream_name, offset,
                                    start_data, mask, step, recycle_cnt, mode="INCR"):
        """
        给指定流的对应偏移设置range modifier
        :param port_index: 测试仪端口索引，例如 1/37
        :param stream_name: 测试流名称, 同一个端口的多条流名称不能相同
        :param offset: 偏移量, 可以通过hdr_name.filed来指定, 例如: outter_udp.sourcePort
        :param start_data: 初始数据
        :param mask: 数据掩码, 对于IP 255.255.255.255, 对于vni: (1<< 24) - 1
        :param mode: 模式, 支持 "INCR" 以及 ”DECR"
        :param step: 变化步长, 对于ip: "0.0.0.1" 对于数值类型 “1”
        :param recycle_cnt: 循环数量 
        """
        dict_request = {
            "instance_name": self.instance_name,
            "port_index": port_index,
            "stream_name": stream_name,
            "offset": offset,
            "start_data": start_data,
            "mask": mask,
            "mode": mode,
            "step": step,
            "recycle_cnt": recycle_cnt,
        }

        grpc_ret = self.spirent_grpc_client.grpc_call("pushRangeModifier", dict_request)
        self.assert_("spirent push range modifier faild", grpc_ret["info"] == "success")

    def _parse_arp_pkt(self, pkt: ARP):
        arp_info = {}
        arp_info['hwtype'] = pkt.hwtype
        arp_info['ptype'] = pkt.ptype
        arp_info['hwlen'] = pkt.hwlen
        arp_info['plen'] = pkt.plen
        arp_info['hwsrc'] = pkt.hwsrc
        arp_info['psrc'] = pkt.psrc
        arp_info['hwdst'] = pkt.hwdst
        arp_info['pdst'] = pkt.pdst
        return arp_info

    def init_spirent(self, port_index, local_ip, peer_ip):
        self.enable_spirent()
        self.spirent_init(settings.SPIRENT_CHASSIP)
        self.spirent_create_port(port_index)
        self.spirent_attach_port(port_index)
        self.spirent_create_l3_device(port_index, "l3_dev_1", local_ip = local_ip, peer_ip = peer_ip)

    def release_spirent(self, port_index):
        self.spirent_detach_port(port_index)
        self.spirent_delete_port(port_index)

    def start_spirent_burst(self, port_index, pkt_num=1):
        self.spirent_config_burst_generator(port_index, pkt_num = pkt_num)
        self.spirent_start_nd_arp(port_index)
        self.spirent_start_traffic(port_index)
        self.spirent_wait_traffic_complete(port_index)
        self.spirent_stop_traffic(port_index)

    def start_spirent_continuous(self, port_index, load=0.01):
        self.spirent_config_continue_generator(port_index, str(load))
        self.spirent_start_nd_arp(port_index)
        self.spirent_start_traffic(port_index)

    def create_spirent_vxlan_header(self, port_index, stream_name, ud_dip, vni, pkt_len=512):
        """
        创建一个Spirent测试设备的VXLAN头部 并将其添加到一个指定的端口和流中。
        Args:
            port_index (int): 端口索引,用于指定要添加VXLAN头部的端口。
            stream_name (str): 流名称,用于指定要添加VXLAN头部的流。
            ud_dip (str): underlay 目的IP地址,用于设置IPv4头部的目的IP地址。
            vni (int): VNI,用于设置VXLAN头部的VNI。
        Returns:
            None
        """
        self.spirent_create_stream(port_index, stream_name, min_frame_len=pkt_len, max_frame_len=pkt_len)
        self.spirent_push_ethhdr(port_index, stream_name, hdr_name="outer_eth", src_mac = "00:00:20:00:00:00", dst_mac = settings.SPIRENT_PEER_MAC)
        self.spirent_push_iphdr(port_index, stream_name, hdr_name="outer_ipv4", src_ip = "192.85.1.2", dst_ip = ud_dip)
        self.spirent_push_udphdr(port_index, stream_name, hdr_name="outer_udp", src_port = 1024, dst_port = 4789)
        self.spirent_push_vxlanhdr(port_index, stream_name, hdr_name="vxlan_hdr", vni = vni)
        self.spirent_push_ethhdr(port_index, stream_name, hdr_name="inner_eth", src_mac = self.qta_send_ov_smac, dst_mac = self.qta_send_ov_dmac)
        self.spirent_push_range_modifier(port_index, stream_name, offset="outer_ipv4.src_ip", start_data = "192.85.1.2", mask = "255.255.255.255", step = "0.0.0.1", recycle_cnt = 1000)

    def create_spirent_udp_pkt(self, port_index, stream_name, sip, dip, sport=1234, dport=5678, sport_num=1, dport_num=1):
        """
        创建一个UDP数据包,并将其添加到一个指定的端口和流中。

        Args:
            port_index (int): 端口索引,用于指定要添加UDP数据包的端口。
            stream_name (str): 流名称,用于指定要添加UDP数据包的流。
            sip (str): 源IP地址,用于设置IPv4头部的源IP地址。
            dip (str): 目的IP地址,用于设置IPv4头部的目的IP地址。
            sport (int): 源端口号,用于设置UDP头部的源端口,默认为1234。
            dport (int): 目的端口号,用于设置UDP头部的目的端口号,默认为5678。
            sport_num (int): 源端口号数量,用于设置多个源端口号,默认为1。
            dport_num (int): 目的端口号数量,用于设置多个目的端口号,默认为1。

        Returns:
            None
        """
        self.spirent_push_iphdr(port_index, stream_name, hdr_name="inner_ipv4",  src_ip = sip, dst_ip = dip)
        self.spirent_push_udphdr(port_index, stream_name, hdr_name="inner_udp", src_port = sport, dst_port = dport)

        if sport_num > 1:
            self.spirent_push_range_modifier(port_index, stream_name, offset="inner_udp.src_port", start_data = str(sport), mask = str((1<<16) - 1), step = "1", recycle_cnt = sport_num)
        if dport_num > 1:
            self.spirent_push_range_modifier(port_index, stream_name, offset="inner_udp.dst_port", start_data = str(dport), mask = str((1<<16) - 1), step = "1", recycle_cnt = dport_num)

    def _parse_vxlan_pkt(self, pkt, ignore_ov_mac, ignore_inner_eth_type=True, ignore_ov_mss=True):
        m_stream_info = {}
        if not pkt.haslayer(Ether):
            return None
        l3 = pkt[Ether].payload
        # if l3.haslayer(ARP):
        #     m_stream_info["arp"] = self._parse_arp_pkt(pkt)
        #     return m_stream_info 

        if not l3.haslayer(IP):
            return None
        m_stream_info["len"] = len(pkt)
        m_stream_info["ud_sip"] = l3[IP].src
        m_stream_info["ud_dip"] = l3[IP].dst
        l4 = l3[IP].payload
        if not l4.haslayer(UDP):
            return None
        if (l4[UDP].dport != 4789):
            return None
        vxlan_pkt = l4[UDP].payload
        if not vxlan_pkt.haslayer(VXLAN):
            return None
        m_stream_info["ud_vni"] = vxlan_pkt[VXLAN].vni
        ov_l2 = vxlan_pkt[VXLAN].payload

        if not ov_l2.haslayer(Ether):
            return None
        if ignore_ov_mac:
            m_stream_info["ov_smac"] = ""
            m_stream_info["ov_dmac"] = ""
        else:
            m_stream_info["ov_smac"] = ov_l2[Ether].src
            m_stream_info["ov_dmac"] = ov_l2[Ether].dst
            if ignore_inner_eth_type == False:
                m_stream_info["eth_type"] = ov_l2[Ether].type
        ov_l3 = ov_l2[Ether].payload

        if ov_l3.haslayer(IP):
            m_stream_info["ov_sip"] = ov_l3[IP].src
            m_stream_info["ov_dip"] = ov_l3[IP].dst
            m_stream_info["ov_ttl"] = ov_l3[IP].ttl
            ov_l4 = ov_l3[IP].payload

            if ov_l4.haslayer(UDP):
                m_stream_info["proto"] = "udp"
                m_stream_info["ov_sport"] = ov_l4[UDP].sport
                m_stream_info["ov_dport"] = ov_l4[UDP].dport
            elif ov_l4.haslayer(TCP):
                m_stream_info["proto"] = "tcp"
                m_stream_info["ov_sport"] = ov_l4[TCP].sport
                m_stream_info["ov_dport"] = ov_l4[TCP].dport
                if not ignore_ov_mss and ov_l4[TCP].options and ov_l4[TCP].options[0][0] == 'MSS':
                    m_stream_info['mss'] = ov_l4[TCP].options[0][1]
            elif ov_l4.haslayer(ICMP):
                m_stream_info["proto"] = "icmp"
        elif ov_l3.haslayer(IPv6): 
            m_stream_info["ov_sip"] = ov_l3[IPv6].src
            m_stream_info["ov_dip"] = ov_l3[IPv6].dst
            m_stream_info["ov_ttl"] = ov_l3[IPv6].hlim
            ov_l4 = ov_l3[IPv6].payload

            if ov_l4.haslayer(UDP):
                m_stream_info["proto"] = "udp"
                m_stream_info["ov_sport"] = ov_l4[UDP].sport
                m_stream_info["ov_dport"] = ov_l4[UDP].dport
            elif ov_l4.haslayer(TCP):
                m_stream_info["proto"] = "tcp"
                m_stream_info["ov_sport"] = ov_l4[TCP].sport
                m_stream_info["ov_dport"] = ov_l4[TCP].dport
            elif ov_l4.haslayer(ICMPv6EchoReply):
                m_stream_info["proto"] = "icmp"
            elif ov_l4.haslayer(ICMPv6EchoRequest):
                m_stream_info["proto"] = "icmp"
        elif ov_l3.haslayer(ARP):
            m_stream_info["arp"] = self._parse_arp_pkt(pkt)
            return m_stream_info
        else:
            return m_stream_info

        return m_stream_info

    def _parse_gre_pkt(self, pkt, ignore_ov_mss=True):
        m_stream_info = {}
        if not pkt.haslayer(Ether):
            return None
        l3 = pkt[Ether].payload
        if not l3.haslayer(IP):
            return None
        m_stream_info["len"] = len(pkt)
        m_stream_info["ud_sip"] = l3[IP].src
        m_stream_info["ud_dip"] = l3[IP].dst
        gre_pkt = l3[IP].payload
        if not gre_pkt.haslayer(GRE):
            return None
        m_stream_info["vpcid"] = gre_pkt[GRE].key
        ov_l3 = gre_pkt[GRE].payload

        if ov_l3.haslayer(IP):
            m_stream_info["ov_sip"] = ov_l3[IP].src
            m_stream_info["ov_dip"] = ov_l3[IP].dst
            m_stream_info["ov_ttl"] = ov_l3[IP].ttl
            ov_l4 = ov_l3[IP].payload

            if ov_l4.haslayer(UDP):
                m_stream_info["proto"] = "udp"
                m_stream_info["ov_sport"] = ov_l4[UDP].sport
                m_stream_info["ov_dport"] = ov_l4[UDP].dport
            elif ov_l4.haslayer(TCP):
                m_stream_info["proto"] = "tcp"
                m_stream_info["ov_sport"] = ov_l4[TCP].sport
                m_stream_info["ov_dport"] = ov_l4[TCP].dport
                if not ignore_ov_mss and ov_l4[TCP].options and ov_l4[TCP].options[0][0] == 'MSS':
                    m_stream_info['mss'] = ov_l4[TCP].options[0][1]
            elif ov_l4.haslayer(ICMP):
                m_stream_info["proto"] = "icmp"
        elif ov_l3.haslayer(IPv6): 
            m_stream_info["ov_sip"] = ov_l3[IPv6].src
            m_stream_info["ov_dip"] = ov_l3[IPv6].dst
            m_stream_info["ov_ttl"] = ov_l3[IPv6].hlim
            ov_l4 = ov_l3[IPv6].payload

            if ov_l4.haslayer(UDP):
                m_stream_info["proto"] = "udp"
                m_stream_info["ov_sport"] = ov_l4[UDP].sport
                m_stream_info["ov_dport"] = ov_l4[UDP].dport
            elif ov_l4.haslayer(TCP):
                m_stream_info["proto"] = "tcp"
                m_stream_info["ov_sport"] = ov_l4[TCP].sport
                m_stream_info["ov_dport"] = ov_l4[TCP].dport
            elif ov_l4.haslayer(ICMPv6EchoReply):
                m_stream_info["proto"] = "icmp"
            elif ov_l4.haslayer(ICMPv6EchoRequest):
                m_stream_info["proto"] = "icmp"
        else:
            return None

        return m_stream_info

    def start_capture(self, vrfname, sip, dip, sport, dport, proto, both, pkt_len, sample, loop, mac_type="any"):
        self.ntb_ssh_client.exec_cmd("config ntb capture stop")
        cmd_str = "config ntb capture start"
        vrfname_option = ""
        sip_option = ""
        dip_option = ""
        sport_option = ""
        dport_option = ""
        proto_option = ""
        both_option = ""
        pkt_len_option = ""
        sample_option = ""
        loop_option = ""
        if vrfname != "":
            vrfname_option = " --vrfname %s" % vrfname
        if sip != "":
            sip_option = " --srcip %s" % sip
        if dip != "":
            dip_option = " --dstip %s" % dip
        if sport != "":
            sport_option = " --srcport %s" % sport
        if dport != "":
            dport_option = " --dstport %s" % dport
        if proto != "":
            proto_option = " --proto %s" % proto
        if both == True:
            both_option = " --both"
        if pkt_len != "":
            pkt_len_option = " --pkt_len %s" % pkt_len
        if sample != "":
            sample_option = " --sample %s" % sample
        if loop == True:
            loop_option = " --loop"
        if mac_type != 0:
            mac_type_option = " --mac_type %s"%(mac_type) # mac_type: ipv4/ipv6/arp/lldp/lacp
        cmd_str = cmd_str + vrfname_option + sip_option + dip_option + sport_option + dport_option + proto_option + both_option + pkt_len_option + sample_option + loop_option + mac_type_option
        print(cmd_str)

        out, err = self.ntb_ssh_client.exec_cmd(cmd_str)
        if err != "" or out.decode() != "":
            return False
        return True

    def stop_capture(self):
        cmd_str = "config ntb capture stop"
        out, err = self.ntb_ssh_client.exec_cmd(cmd_str)
        if err != "" or out.decode() != "":
            return False
        return True

    def set_batch_config_size(self, size):
        cmd_str = f"config ntb batch size {size}"
        out, err = self.ntb_ssh_client.exec_cmd(cmd_str)
        if err != "" or out.decode() != "":
            return False
        return True

    def get_batch_config_size(self):
        cmd_str = f"show ntb batch size"
        out, err = self.ntb_ssh_client.exec_cmd(cmd_str)
        return out

    def dump_capture_file(self, ignore_ov_mac=False, path=None, ignore_eth_type=True):
        vxlan_pkts = []
        gre_pkts = []
        self.local_capture_path = settings.ROOT_PATH + "/%s-capture.pcap0" % (settings.NTB_CNTL_VIP)
        self.remote_path = "/usr/local/ntb/capture/%s-capture.pcap0" % (settings.NTB_CNTL_VIP)
        self.ntb_ssh_client.scp_get_cmd(self.remote_path, self.local_capture_path)
        if path is not None:
            self.local_capture_path = path
        scapy_caps = rdpcap(self.local_capture_path)
        for packet in scapy_caps:
            m_stream_info = self._parse_vxlan_pkt(packet, ignore_ov_mac, ignore_eth_type)
            if m_stream_info is not None:
                vxlan_pkts.append(m_stream_info)
            m_stream_info = self._parse_gre_pkt(packet)
            if m_stream_info is not None:
                gre_pkts.append(m_stream_info)

        return vxlan_pkts, gre_pkts

    def reset_all_filters(self):
        testutils.reset_filters()

    def add_vxlan_filter(self):
        testutils.add_filter(testutils.vxlan_filter)

    def add_gre_filter(self):
        testutils.add_filter(testutils.gre_filter)
        
    def add_vxlan_and_gre_filter(self):
        testutils.add_filter(testutils.vxlan_and_gre_filter)

    def add_underlay_sip_filter(self, sip=settings.NTB_FWD_VIP):
        global filter_underlay_sip
        filter_underlay_sip = sip
        testutils.add_filter(underlay_sip_fwdip_filter)
