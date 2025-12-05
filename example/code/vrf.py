# -*- coding: utf-8 -*-
'''vrf grpc 测试用例
'''
# 2021/03/05 QTAF自动生成

# ----------------------------------------------------------------------------------#
# cmd
# python manage.py runtest ntbtest.grpc.vrf
# ----------------------------------------------------------------------------------#

from testbase.testcase import debug_run_all
from ntbtest.ntb_test_base import *
from utils.utils import *


class VrfTest(NTBTestBase):
    '''
    vrf grpc test case
    '''
    owner = "auto"
    timeout = 30
    priority = NtbTestCase.EnumPriority.High
    status = NtbTestCase.EnumStatus.Design

    def pre_test(self):
        super(VrfTest, self).pre_test()
    
    def constuct_test_gre_routes(self, rt_num):
        gre_routes = []
        rt_prefix_start = ip_to_int("1.1.1.1")

        for rt_pfx in range(rt_prefix_start, rt_prefix_start + rt_num):
            rt_info = {}
            rt_info["prefix"] = int_to_ip(rt_pfx)
            rt_info["plen"] = 32
            rt_info["vpcid"] = 100000
            rt_info["nexthop"] = "11.103.54.23"
            rt_info["expect_res"] = "success"
            gre_routes.append(rt_info)
        rt_prefix_start = rt_prefix_start + rt_num 
        return gre_routes

    def run_test(self):
        # ----------------------------------------------------------------------------------#
        self.start_step("1.增删功能测试")
        vrfname = "qta_test_vrf"
        self.create_vrf(vrfname, expect_res="success")
        self.delete_vrf(vrfname, expect_res="success")

        # ----------------------------------------------------------------------------------#
        self.start_step("2.幂等性测试")
        vrfname = "qta_test_vrf"

        self.create_vrf(vrfname, expect_res="success")
        self.create_vrf(vrfname, expect_res="success")

        self.delete_vrf(vrfname, expect_res="success")
        self.delete_vrf(vrfname, expect_res="success")

        # ----------------------------------------------------------------------------------#
        self.start_step("3.参数合法性测试")
        #vrfname 为空
        vrfname = ""
        self.create_vrf(vrfname, expect_res="VRF name is invalid")
        #vrfname 长度为1
        vrfname = get_str_of_spec_len(1)
        self.create_vrf(vrfname, expect_res="success")
        self.delete_vrf(vrfname, expect_res="success")
        #vrfname 长度为63
        vrfname = get_str_of_spec_len(63)
        self.create_vrf(vrfname, expect_res="success")
        self.delete_vrf(vrfname, expect_res="success")
        #vrfname 长度为64
        vrfname = get_str_of_spec_len(64)
        self.create_vrf(vrfname, expect_res="VRF name is invalid")
        self.delete_vrf(vrfname, expect_res="VRF name is invalid")
        #vrfname 设置为数字
        vrfname = "12345"
        self.create_vrf(vrfname, expect_res="success")
        self.delete_vrf(vrfname, expect_res="success")
        #vrfname 空格
        vrfname = " "
        self.create_vrf(vrfname, expect_res="VRF name is invalid")
        self.delete_vrf(vrfname, expect_res="VRF name is invalid")
        #vrfname 首字母为空格
        vrfname = " qta_test_vrf"
        self.create_vrf(vrfname, expect_res="VRF name is invalid")
        self.delete_vrf(vrfname, expect_res="VRF name is invalid")

        # ----------------------------------------------------------------------------------#
        self.start_step("4.不同路由数量时vrf异步删除接口测试")
        vrfname = "qta_test_vrf"
        self.create_vrf(vrfname, expect_res="success")
        self.create_gre_route(vrfname, self.constuct_test_gre_routes(30000))
        self.delete_vrf(vrfname, expect_res="success")

        self.create_vrf(vrfname, expect_res="success")
        self.create_gre_route(vrfname, self.constuct_test_gre_routes(50000))
        self.delete_vrf(vrfname, expect_res="success")

        self.create_vrf(vrfname, expect_res="success")
        self.create_gre_route(vrfname, self.constuct_test_gre_routes(100000))
        self.delete_vrf(vrfname, expect_res="success")

        self.create_vrf(vrfname, expect_res="success")
        self.create_gre_route(vrfname, self.constuct_test_gre_routes(200000))
        self.delete_vrf(vrfname, expect_res="success")

        self.create_vrf(vrfname, expect_res="success")
        self.create_gre_route(vrfname, self.constuct_test_gre_routes(300000))
        self.delete_vrf(vrfname, expect_res="success")

        self.create_vrf(vrfname, expect_res="success")
        self.create_gre_route(vrfname, self.constuct_test_gre_routes(500000))
        self.delete_vrf(vrfname, expect_res="success")

        self.create_vrf(vrfname, expect_res="success")
        self.create_gre_route(vrfname, self.constuct_test_gre_routes(30))
        self.delete_vrf(vrfname, expect_res="success")

        while True:
            vrf_brief_infos = self.get_vrf_brief_info()
            if vrfname not in vrf_brief_infos:
                break
            print(vrf_brief_infos[vrfname])
            time.sleep(10)

        # ----------------------------------------------------------------------------------#
        self.start_step("4.多个异步并发删除任务测试")

        for index in range(1, 4):
            vrfname = "qta_test_vrf_%d" % index
            self.create_vrf(vrfname, expect_res="success")

        for index in range(1, 4):
            vrfname = "qta_test_vrf_%d" % index
            self.create_gre_route(vrfname, self.constuct_test_gre_routes(100000))

        for index in range(1, 4):
            vrfname = "qta_test_vrf_%d" % index
            self.delete_vrf(vrfname, expect_res="success")

        while True:
            is_over = True
            vrf_brief_infos = self.get_vrf_brief_info()
            for index in range(1, 4):
                vrfname = "qta_test_vrf_%d" % index
                if vrfname in vrf_brief_infos:
                    is_over = False
                    break
            if is_over:
                break
            print(vrf_brief_infos[vrfname])
            time.sleep(10)

    def post_test(self):
        super(VrfTest, self).post_test()

if __name__ == '__main__':
    debug_run_all()
