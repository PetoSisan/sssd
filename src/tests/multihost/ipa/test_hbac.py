""" IPA hbac test cases

:requirement: HBAC (ipa_provider)
:casecomponent: sssd
:subsystemteam: sst_idm_sssd
:upstream: yes
:status: approved
"""
import pytest
import time
import re
from sssd.testlib.ipa.utils import ipaTools
from sssd.testlib.common.utils import sssdTools
from sssd.testlib.common.expect import pexpect_ssh


@pytest.mark.usefixtures('default_ipa_users',
                         'disable_allow_all_hbac',
                         'reset_password')
@pytest.mark.tier2
@pytest.mark.hbac
class Testipahbac(object):

    def test_hbac_refresh_time(self, multihost):
        """
        :title: hbac: Verify cached hbac rule is applied
         for the refresh time period
        :id: c839fd33-65da-4252-82cf-5ba88ad02f55
        """
        ipa_server = ipaTools(multihost.master[0])
        ipa_client = ipaTools(multihost.client[0])
        sssd_client = sssdTools(multihost.client[0])
        domain_name = '%s/%s' % ('domain',
                                 sssd_client.get_domain_section_name())
        client_host = multihost.client[0].sys_hostname
        pexpect_ssh(client_host, 'foobar1', 'Secret123', debug=False)
        ipa_server.add_hbac_rule('test1', 'foobar1', client_host, 'sshd')
        multihost.client[0].service_sssd('stop')
        sssd_client.remove_sss_cache('/var/lib/sss/db')
        hbac_params = {'ipa_hbac_refresh': '60'}
        sssd_client.sssd_conf(domain_name, hbac_params)
        multihost.client[0].service_sssd('start')
        login_status = ipa_client.ssh_login('foobar1', 'Secret123',
                                            client_host, command='id')
        if login_status:
            status = 'PASS'
        # update the rule
        update_rule = "ipa hbacrule-remove-user --users='foobar1' test1"
        # sleep for 20 seconds
        time.sleep(20)
        multihost.master[0].run_command(update_rule)
        login_status = ipa_client.ssh_login('foobar1', 'Secret123',
                                            client_host, command='id')
        if login_status:
            status = 'PASS'
        time.sleep(45)
        # now it should not allow login
        login_status = ipa_client.ssh_login('foobar1', 'Secret123',
                                            client_host)
        if not login_status:
            status = 'PASS'
        sssd_client.sssd_conf(domain_name, hbac_params, action='delete')
        multihost.client[0].service_sssd('restart')
        ipa_server.del_hbac_rule('test1')
        assert status == 'PASS'

    def test_auto_private_group(self, multihost):
        """
        :title: hbac: Verify hbac rule associated with
         User private Groups
        :id: 99904ccd-bf2f-4c09-9636-92e036e19a0e
        """
        ipa_server = ipaTools(multihost.master[0])
        sssd_client = sssdTools(multihost.client[0])
        domain_name = '%s/%s' % ('domain',
                                 sssd_client.get_domain_section_name())
        client_host = multihost.client[0].sys_hostname
        pexpect_ssh(client_host, 'foobar1', 'Secret123', debug=False)
        multihost.client[0].service_sssd('stop')
        sssd_client.remove_sss_cache('/var/lib/sss/db')
        enable_pvtgroups = {'auto_private_groups': 'True'}
        sssd_client.sssd_conf(domain_name, enable_pvtgroups)
        multihost.client[0].service_sssd('start')
        cmd = 'ipa group-add std_group'
        multihost.master[0].run_command(cmd)
        # Add members
        cmd1 = 'ipa group-add-member --users=foobar1 std_group'
        multihost.master[0].run_command(cmd1, raiseonerr=False)
        # add rule
        ipa_server.add_hbac_rule('allow_ssh_access', 'std_group',
                                 client_host, 'sshd', group=True)
        sssctl_cmd = 'sssctl user-checks -s sshd foobar1'
        cmd1 = multihost.client[0].run_command(sssctl_cmd)
        test_pam = re.compile(r'%s' % 'pam_acct_mgmt: Success')
        result = test_pam.search(cmd1.stderr_text)
        if not result:
            STATUS = 'FAIL'
        else:
            STATUS = 'PASS'
        ipa_server.del_hbac_rule('allow_ssh_access')
        cmd = 'ipa group-del std_group'
        multihost.master[0].run_command(cmd)
        sssd_client.sssd_conf(domain_name, enable_pvtgroups, action='delete')
        multihost.client[0].service_sssd('restart')
        assert STATUS == 'PASS'
