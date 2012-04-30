# Copyright 2012 Dimosthenes Fioretos dfiore -at- noc -dot- edunet -dot- gr
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


# The cream endpoint to be used (e.g.: ctb04.gridctb.uoa.gr:8443 )
ce_endpoint=""

# The cream queue to be used (e.g.: cream-pbs-see )
cream_queue=""

# The CREAM endpoint in use for delegation (e.g.: https://ctb04.gridctb.uoa.gr:8443//ce-cream/services/gridsite-delegation )
deleg_endpoint=""

# The user's submitting the jobs virtual organisation (e.g.: see )
vo=""

# The user's submitting the jobs proxy password (e.g.: p4sSw0rD )
proxy_pass=""

# Gridftp server used for data transfers (e.g.: se01.isabella.grnet.gr )
gridftp_server=""

# LFC directory for data transfers. This directory will be created, it doesn't have to allready exist. Example: /grid/dteam/cream_testing
lfn_dir=""

# A delegation id string (e.g.: my_deleg_id )
deleg_id=""

# The log level used during the test.Default is INFO.For extra output,set to DEBUG or TRACE.
# (possible values: NONE FAIL WARN INFO DEBUG TRACE)
log_level="TRACE"

#The underlying batch system of the CREAM endpoint.Either pbs or lsf.
batch_system=""

# A directory in the gridftp server.This directory has to allready exist and your vo have write access to it. Used for OSB file storage. Example: /tmp
gridftp_dir="/tmp"

# The hostname where the lrms is running. Example: ctb07.gridctb.uoa.gr
lrms_host=""

# A user on the lrms host, who has job admin priviledges and ssh access to the machine. Example: root
lrms_admin_user=""

# The aforementioned user's ssh password. Example: p4sSw0rD
lrms_admin_pass=""

# The path in which temporary files will reside.
# They will be automatically cleaned up unless you set the variable delete_files to "False" or explicitely don't run the cleanup test case.
# The path will be created -with its parents-, it doesn't have to exist. You can leave it empty and a temporary directory will be created for you.
# In order to know which temp random directory is used, it is printed in standard output and in the final test suite report.
# Warning: any parent directories created, are not removed! 
# All in all, unless needed for specific reasons, you should leave this variable empty.
tmp_dir=""

# Delete temporary files (jdl and script files created during the test) or not. Possible values: True False. Defaults to "False"
delete_files="False"

# The cream host's root user's ssh password. Example: p4sSw0rD
cream_root_pass=""

# Path to a second certificate
sec_cert=""

# Path to a second key
sec_key=""

# Password for the second certificate
sec_proxy_pass=""

# The cream db host
creamdb_host=""

#The cream db port. Defaults to 3306.
creamdb_port="3306"

# The user to read the cream db
creamdb_user=""

# The db pass
creamdb_pass=""

# The authorization model in use. Either gjaf or argus
authz_model=""

# The host of the argus service
argus_host=""

# Root user password for ssh access on argus host
argus_root_pass=""

# The version of the middleware being tested. Either EMI1 or EMI2.
middleware_version=""

# The ldap port for the CREAM resource bdii. Defaults to 2170.
cream_ldap_port="2170"

# The LFC_HOST env var to be set on the WN for outputdata operations. Example: prod-lfc-shared-central.cern.chs
lfc_host=''

# The LCG_GFAL_INFOSYS env var to be set on the WN for outputdata operations. Example: prod-bdii.cern.ch:2170
lcg_gfal_infosys=''

#########################################
#
# Variable checking/setting code follows.
# Do not edit. (unless you know what and why you are doing it!)
#
#########################################
# do not change this variable
ce=ce_endpoint + "/" + cream_queue

import os as _os       # underscored libs aren't included into rf when the module itself is loaded
import tempfile as _tf # same as above


class _error(Exception):
	def __init__(self,string):
		self.string = string
	def __str__(self):
		return str(self.string)

if tmp_dir == "" or tmp_dir[0] != '/' or tmp_dir == "/tmp" or tmp_dir == "/tmp/":
        tmp_dir = _tf.mkdtemp(suffix=".cream_testing", dir="/tmp/") + '/'
else:
        if tmp_dir[-1] != '/':
                tmp_dir += '/'
        _os.system("mkdir -p " + tmp_dir) #this should work under normal circumstances, the code here is kept minimal after all.
print "INFO: The files of this testsuite will be stored under: " + tmp_dir
outputdata_dir = tmp_dir + 'outputdata'
_os.system("mkdir -p " + outputdata_dir) #this should work under normal circumstances, the code here is kept minimal after all.

all_vars = { "ce_endpoint":ce_endpoint, "cream_queue":cream_queue, "deleg_endpoint":deleg_endpoint, "vo":vo, "proxy_pass":proxy_pass,
             "gridftp_server":gridftp_server, "lfn_dir":lfn_dir, "deleg_id":deleg_id, "log_level":log_level, "batch_system":batch_system,
             "gridftp_dir":gridftp_dir, "lrms_host":lrms_host, "lrms_admin_user":lrms_admin_user, "lrms_admin_pass":lrms_admin_pass,
             "tmp_dir":tmp_dir, "delete_files":delete_files, "cream_root_pass":cream_root_pass, "sec_cert":sec_cert, "sec_key":sec_key,
             "sec_proxy_pass":sec_proxy_pass, "creamdb_host":creamdb_host, "creamdb_port":creamdb_port, "creamdb_user":creamdb_user,
             "creamdb_pass":creamdb_pass, "authz_model":authz_model, "argus_host":argus_host, "argus_root_pass":argus_root_pass,
             "middleware_version":middleware_version, "cream_ldap_port":cream_ldap_port, "tmp_dir":tmp_dir }

for key, value in all_vars.iteritems():
        #print key + '=' + value
        if value == "":
                if key in "ce_endpoint cream_queue vo proxy_pass":
                        raise _error('Mandatory variable "' + key + '" not set! Aborting...')
                else:
                        print 'INFO: Non-mandatory variable "' + key + '" has not been set.'
        if key == "middleware_version":
                if value.lower() != 'emi1' and value.lower() != 'emi2':
                        raise _error('Middleware version variable must be either "EMI1" or "EMI2"')
        if key == "authz_model":
                if value != 'argus' and value != 'gjaf':
                        raise _error('Authorization model variable must be either "argus" or "gjaf"')
        if key == "delete_files":
                if value.lower() != "true" and value.lower() != "false":
                        delete_files = "True"
        if key == "log_level":
                valid_loglevels = ["NONE", "FAIL", "WARN", "INFO", "DEBUG", "TRACE"]
                if value not in valid_loglevels:
                        print 'INFO: Log level must be one of: NONE FAIL WARN INFO DEBUG TRACE. You entered: ' + log_level
                        print '      Log level is auto-corrected to DEBUG'
                        log_level = 'DEBUG'
        if key == "batch_system":
                if value != "pbs" and value != "lsf":
                        raise _error('Batch system must be either "pbs" or "lsf". You entered: ' + batch_system)
