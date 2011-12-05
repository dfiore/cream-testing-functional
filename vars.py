# Copyright 2011 Dimosthenes Fioretos dfiore -at- noc -dot- edunet -dot- gr
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
log_level=""

#The underlying batch system of the CREAM endpoint.Either pbs or lsf.
batch_system=""

# A directory in the gridftp server.This directory has to allready exist and your vo have write access to it. Used for OSB file storage. Example: /tmp
gridftp_dir=""

# The hostname where TORQUE is running. Example: ctb07.gridctb.uoa.gr
torque_host=""

# A user on the TORQUE host, who has job admin priviledges and ssh access to the machine. Example: root
torque_admin_user=""

# The aforementioned user's ssh password. Example: p4sSw0rD
torque_admin_pass=""

# The path in which temporary files will reside.
# They will be automatically cleaned up unless you set the variable delete_files to "False" or explicitely don't run the cleanup test case.
# The path will be created -with its parents-, it doesn't have to exist. You can leave it empty and a temporary directory will be created for you.
# In order to know which temp random directory is used, it is printed in standard output and in the final test suite report.
# Warning: any parent directories created, are not removed! 
# All in all, unless needed for specific reasons, you should leave this variable empty.
tmp_dir=""

# Delete temporary files (jdl and script files created during the test) or not. Possible values: True False. Defaults to "True"
delete_files="False"

# The cream host's root user's ssh password. Example: p4sSw0rD
cream_root_pass=""

# Path to a second certificate
sec_cert=""

# Path to a second key
sec_key=""

# Password for the second certificate
sec_proxy_pass=""

# do not change this variable
ce=ce_endpoint + "/" + cream_queue


#########################################
#
# Variable checking/setting code follows.
# Do not edit. (unless you know what and why you are doing it!)
#
#########################################
import os as _os       # underscored libs aren't included into rf when the module itself is loaded
import tempfile as _tf # same as above

class _error(Exception):
	def __init__(self,string):
		self.string = string
	def __str__(self):
		return str(self.string)

if batch_system != "pbs" and batch_system != "lsf":
        raise _error('Batch system must be either "pbs" or "lsf". You entered: ' + batch_system)

if log_level != "NONE" and log_level != "FAIL" and log_level != "WARN" and log_level != "INFO" and log_level != "DEBUG" and log_level != "TRACE":
        raise _error('Log level must be one of: NONE FAIL WARN INFO DEBUG TRACE. You entered: ' + log_level)

if tmp_dir == "" or tmp_dir[0] != '/' or tmp_dir == "/tmp" or tmp_dir == "/tmp/":
        tmp_dir = _tf.mkdtemp(suffix=".cream_testing", dir="/tmp/") + '/'
else:
        if tmp_dir[-1] != '/':
                tmp_dir += '/'
        _os.system("mkdir -p " + tmp_dir) #this should work under normal circumstances, the code here is kept minimal after all.
print "The files of this testsuite will be stored under: " + tmp_dir

if delete_files != "True" and delete_files != "False":
        delete_files = "True"
