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


'''
Job Handling
--
submit_job() cancel_job() suspend_job() resume_job() submit_and_wait()
cancel_all_jobs() purge_all_jobs() suspend_all_jobs() resume_all_jobs()
get_final_status() get_current_status() get_current_status_verbose()
list_jobs() wait_for_status() job_status_should_be()
qdel_job()

Proxy Handling
--
create_proxy() check_proxy() destroy_proxy() proxy_info()
create_delegation() destroy_delegation()

Data Manipulation
--
lfc_mkdir() lcg_cr() lfc_ls() lcg_cp() lcg_del() lfc_rmdir()
execute_uberftp_command()

JDL Creation
--
simple_jdl() sleep_jdl() cpunumber_jdl() hostnumber_jdl() wholenodes_jdl() smpgranularity_jdl()
combo_jdl() localhost_output_jdl() environment_jdl() osb_basedesturi_jdl() isb_client_to_ce_jdl()
osb_desturi_jdl() prologue_jdl() epilogue_jdl() isb_baseuri_jdl() isb_gsiftp_to_ce_jdl()

Utils
--
file_should_contain()
create_dummy_script()
get_osb() fetch_output_files()
check_osb_basedesturi_files() check_osb_desturi_files()
delete_osb_basedesturi_files() delete_osb_desturi_files()
validate_ce_service_info() get_proxy_dn()
get_job_sb()
set_limiter_threshold() reset_limiter_threshold()
ban_user() unban_user()
change_sandbox_transfer_method()
validate_glue()

CREAM Utils
--
ce_service_info() allowed_submission()
enable_cream_admin() disable_cream_admin()
enable_submission() disable_submission()

Implemented methods enumeration:
 1) Create Proxy
 2) Check Proxy
 3) Destroy Proxy
 4) Create Delegation
 5) Destroy Delegation
 7) Submit Job
 7) Submit And Wait
 8) Cancel Job
 9) Suspend Job
10) Resume Job
11) Cancel All Jobs
12) Purge All Jobs
13) Suspend All Jobs
14) Resume All Jobs
15) Get Final Status
16) Get Current Status
17) Get Current Status Verbose
18) List Jobs
19) Get OSB
20) Fetch Output Files
21) Check OSB BaseDestURI Files
22) Delete OSB BaseDestURI Files
23) Check OSB DestURI Files
24) Delete OSB DestURI Files
25) File Should Contain
26) lfc-mkdir
27) lcg-cr
28) lfc-ls
29) lcg-cp
30) lcg-del
31) lfc-rm -r
32) simple_jdl
33) sleep_jdl
34) cpunumber_jdl
35) hostnumber_jdl
36) wholenodes_jdl
37) smpgranularity_jdl
38) combo_jdl
39) localhost_output_jdl
40) environment_jdl
41) osb_basedesturi_jdl
42) isb_client_to_ce_jdl
43) osb_desturi_jdl
44) prologue_jdl
45) epilogue_jdl
46) isb_baseuri_jdl
47) isb_gsiftp_to_ce_jdl
48) create_dummy_script
49) wait_for_status
50) job_status_should_be
51) qdel_job
52) execute_uberftp_command
53) ce_service_info
54) validate_ce_service_info
55) proxy_info
56) get_proxy_dn
57) enable_cream_admin
58) disable_cream_admin
59) allowed submission
60) enable_submission
61) disable_submission
62) get_job_sb
63) set_limiter_threshold
64) reset_limiter_threshold
65) ban_user
66) unban_user
67) change_sandbox_transfer_method
68) validate_glue

Notes:
- Can submit to invalid queue.BLAH will catch the error and glite-ce-job-status will reflect it.glite-ce-job-submit doesn't raise/return any error.
- Listing jobs shows ALL the UNPURGED jobs by a user.This even means OLD jobs. (the automatic purger expunges them every now and then -configurable-)
- If you mannually purge a job,then it is removed from the listing as well.
- Job cancel operations return 0 for malformed jid,for jid not in an acceptable status and even for non-existent jid.It reports the errors on
  screen tho.The exit value could be a bug or it means that the operation itself was "treated" successfuly thus the 0 exit code.
  No proxy time left is reported as a 1 exit status,so it is catchable.
  If the string "ERROR" or "FATAL" or "FAULT" exists in the glite-ce-job-cancel command output,then it is safe to assume the command failed,
  even if an exit status of 0 is returned.
- When a job has recently finished,glite-ce-job-output fails with return code 0 and fault cause:
2011-06-22 16:14:21,258 WARN - JobID [https://ctb04.gridctb.uoa.gr:8443/CREAM412750152]:  MethodName=[jobInfo] Timestamp=[Wed 22 Jun 2011 16:15:07] ErrorCode=[0] Description=[fromDate/toDate mismatch] FaultCause=[N/A]
- Errors seem to not get reported by the glite-delegation-destroy utility,either as a message or a return value,for many abnormal cases,such as non
  existent delegation id,wrond endpoint etc.
'''


import subprocess , shlex , os , sys , time , re , string , paramiko, fileinput




class _error(Exception):
	def __init__(self,string):
		self.string = string
	def __str__(self):
		return str(self.string)
##############################################################################################################################
##############################################################################################################################
def check_proxy(time_left=None):
        '''
                |  Description:  |  Check whether the proxy exists and if it has any time left.                                                  |\n
                |  Arguments:    |  Without any arguments,it checks if the proxy exists and has any time left                                    |
                |                |  With one argument,it checks if the proxy exists and has greater than or equal to the requested time left.    |\n
                |  Returns:      |  nothing                                                                                                      |
        '''

	if os.environ.has_key("X509_USER_PROXY") == False :
		raise _error("Proxy path env. var not set")

	if os.path.exists(os.environ["X509_USER_PROXY"]) == False :
		raise _error("Proxy file not present or inaccessible")

	com="/usr/bin/voms-proxy-info -timeleft"
	args = shlex.split(com.encode('ascii'))
	p = subprocess.Popen( args , shell=False , stderr=subprocess.STDOUT , stdout=subprocess.PIPE )
	fPtr=p.stdout
	proxy_timeleft=int(fPtr.readline())

        if time_left == None:
        	if proxy_timeleft <= 0 :
	        	raise _error("No proxy time left")
        else:
                if proxy_timeleft <= int(time_left) :
	        	raise _error("Proxy has less time than requested (%s seconds) left" % time_left)
##############################################################################################################################
##############################################################################################################################
def create_proxy(password, vo, cert=None, key=None):
        '''
                |  Description:  |  Create a user proxy.                       |\n
                |  Arguments:    |  password  |      the user's proxy password |
                |                |  vo        |      for the voms extention.   |\n
                |  Returns:      |  nothing.                                   |
        '''

        if cert == None and key == None:
                com = "/usr/bin/voms-proxy-init -pwstdin --voms %s" % vo
        elif cert != None and key != None:
                com = "/usr/bin/voms-proxy-init -pwstdin -cert " + cert + " -key " + key + " --voms " + vo
        else:
                raise _error("Wrong arguments for proxy creation: " + password + " " + vo + " " + cert + " " + key)

        args = shlex.split(com.encode('ascii'))
        p = subprocess.Popen( args , shell=False , stderr=subprocess.STDOUT , stdout=subprocess.PIPE , stdin=subprocess.PIPE)
        (outData,inData)=p.communicate(input=password)

        retVal=p.wait()

        #output = outFP.read()

        print 'Command "' + com + '" output follows:'
        print outData

        if retVal != 0 :
                if retVal == 1 :
                        raise _error("Proxy creation failed.Most probably wrong Virtual Organisation was given.")
                elif retVal == 3 :
                        raise _error("Proxy creation failed.Most probably the password provided was not valid.")
                else :
                        raise _error("Proxy creation failed.Reason: Unknown.")
##############################################################################################################################
##############################################################################################################################
def create_delegation(cream_endpoint,delegId):
        '''
                |  Description: |   Delegate user's proxy credentials,to be used later for job submissions. | \n
                |  Arguments:   |   cream_endpoint     |     the cream endpoint                             |
                |               |   delegId            |     the delegation id string                       | \n
                |  Returns:     |   nothing                                                                 |
        '''

        com="/usr/bin/glite-ce-delegate-proxy -e %s %s" % (cream_endpoint,delegId)
        args = shlex.split(com.encode('ascii'))
        p = subprocess.Popen( args , shell=False , stderr=subprocess.STDOUT , stdout=subprocess.PIPE )
        fPtr=p.stdout

        retVal=p.wait()

        output=fPtr.readlines()

        if retVal != 0 :
                raise _error("Delegation failed.Command output:\n %s" % output)
##############################################################################################################################
##############################################################################################################################
def submit_job(jdl_path,ce_endpoint,delegId=None):
        '''
                |  Description: |   Submit a job with automatic or explicit delegation and return it's job id.                      | \n
                |  Arguments:   |   jdl_path      |  path to the jdl file                                                           |
                |               |   ce_endpoint   |  the cream endpoint,containing the queue                                        |
                |               |   delegId       |  if specified,uses the given delegation id, else it uses automatic delegation   | \n
                |  Returns:     |   the resulting cream job id as a string                                                          |
        '''

        if delegId is None:
                com="/usr/bin/glite-ce-job-submit -d -a -r " + ce_endpoint + " " + jdl_path
        else:
                com="/usr/bin/glite-ce-job-submit -d -r " + ce_endpoint + " -D" + delegId + " " + jdl_path
                #note that if the delegation id is invalid,the command will fail without a message and exit code 1.

        args = shlex.split(com.encode('ascii'))

	p = subprocess.Popen( args , shell=False , stderr=subprocess.STDOUT , stdout=subprocess.PIPE )
	fPtr=p.stdout

        retVal=p.wait()

        output=fPtr.readlines()

	#if retVal != 0:
        if "error" in ','.join(output) or "fault" in ','.join(output) or retVal != 0 :
		raise _error("Job submission failed with return value: " + str(p.returncode) + " \nCommand reported: " +  ','.join(output) )
                #kinda rough output creation,maybe should find a better one

        jid=output[-1] #if job submission was succesfull (at this point of code,it is),then the last line of output holds the job id
        jid=jid[:-1]   #to remove the trailing '\n'

        return jid
##############################################################################################################################
##############################################################################################################################
def get_final_status(job_id):
        '''
                |  Description: |   Return the final status of a job,with the use of the glite-ce-job-status command.   |
                |               |   This command will wait until the job is in a final state.                           | \n
                |  Arguments:   |   job_id     |     the job id,as returned by the submit operation.                    | \n
                |  Returns:     |   job's final status as a string.                                                     |
        '''

        running_states = ['IDLE','REGISTERED', 'PENDING', 'RUNNING', 'REALLY-RUNNING', 'HELD']
        final_states = ['DONE-OK', 'DONE-FAILED', 'ABORTED', 'CANCELLED']

        old_status=""
        com="glite-ce-job-status " + job_id
        args = shlex.split(com.encode('ascii'))

        while 1 :
                p = subprocess.Popen( args , stderr=subprocess.STDOUT , stdout=subprocess.PIPE )
                fPtr=p.stdout

                retVal=p.wait()

                output=fPtr.readlines()

                if retVal != 0 or ("FaultCause" in output and "ErrorCode" in output):
                        raise _error("Job status polling failed with return value: " + str(p.returncode) + "\nCommand reported: " + output)


                found=False
                for i in output:
                        if "Status" in i:
                                last_match=i
                                found=True

                if found == False:
			raise _error("Status couldn't be determined for jid " + job_id + ". Command reported: " + ','.join(output))

                if last_match != old_status :
                        split1 = last_match.split('[')
                        split2 = split1[1].split(']')
                        cur_status=split2[0]
                        old_status=last_match

                        time.sleep(1)

                        if cur_status in final_states :
                                return cur_status
##############################################################################################################################
##############################################################################################################################
def get_current_status(job_id):
        '''
                |  Description:  |  Return the current status of a job,with the use of the glite-ce-job-status command. |
                |                |  This function will NOT wait until the job is in a final state.                      | \n
                |  Arguments:    |  job_id          the job id,as returned by the submit operation.                     | \n
                |  Returns:      |  job's status as a string.                                                           |
        '''

        running_states = ['IDLE','REGISTERED', 'PENDING', 'RUNNING', 'REALLY-RUNNING', 'HELD']
        final_states = ['DONE-OK', 'DONE-FAILED', 'ABORTED', 'CANCELLED']

        old_status=""
        com="glite-ce-job-status " + job_id
        args = shlex.split(com.encode('ascii'))

        p = subprocess.Popen( args , stderr=subprocess.STDOUT , stdout=subprocess.PIPE )
        fPtr=p.stdout

        retVal=p.wait()

        output=fPtr.readlines()

        if retVal != 0 or ("FaultCause" in output and "ErrorCode" in output):
                raise _error("Job status polling failed with return value: " + str(p.returncode) + "\nCommand reported: " + output)

        print output

        found=False
        for i in output:
                if "Status" in i:
                        last_match=i
                        found=True

        if found == False:
                raise _error("Status couldn't be determined for jid " + job_id + ". Command reported: " + ','.join(output))


        split1 = last_match.split('[')
        split2 = split1[1].split(']')
        cur_status=split2[0]

        if cur_status in final_states or cur_status in running_states:
                return cur_status
        else :
                raise _error("Illegal job state: " + cur_status)
##############################################################################################################################
##############################################################################################################################
def get_osb(jdl_path):
        '''
                |  Description:  |  Read from a jdl file the list of files contained in the OutputSandBox attribute. |
                |  Arguments:    |  jdl_path        path to the jdl file.                                            |
                |  Returns:      |  a list with the files in the output sandbox                                      |
        '''

        #read jdl file as string
        jdl_as_string=open(jdl_path).read()

        #replace various indifferent syntactic variaties with a certain one,to make string matching easier
        copy1=jdl_as_string.replace(" = ","=")
        copy2=copy1.replace(" =","=")
        copy3=copy2.replace("= ","=")

        #search for the position of the outputsandbox for the three "logically" possible matches (should improve later???)
        pos = copy3.find("OutputSandBox=")
        if pos == -1:
                pos = copy3.find("OutputSandbox=")
                if pos == -1:
                        pos = copy3.find("outputsandbox=")
                        if pos == -1:
                                raise _error("OutputSandbox attribute not set!")

        #print pos

        #get a copy of the string starting where the part that interests us is
        copy4 = copy3[pos:]

        #print copy4

        #extract the file list,between the two braces
        file_list = copy4[copy4.find("{")+1:copy4.find("}")]

        #print file_list

        #extract substrings within quotes (which should be the files in the output sandbox)
        #python extended slicing used,meaning: start at element 1 (1:),finish at the end(::),read every 2 elements (:2).
        result=file_list.split('"')[1::2]       

        #print result

        return result
##############################################################################################################################
##############################################################################################################################
def fetch_output_files(dest_dir,job_id,timeout=0):
        '''
             |  Description: |  Gather the files from a certain job,store them in the specified directory and return the list of files transfered |
             |               |  as they exist on the disk after the transfer operation.                                                           |
             |               |  Note: Target directory must be empty!Any existing output files with the same name are overwritten!                | \n
             |  Arguments:   |  dest_dir     |   directory to store the files locally                                                                |
             |               |  job_id       |   the job's cream job id                                                                              |
          |               |  timeout      |   time to wait before fetching output (used to wait until files are uploaded to CE's gridftp server)  | \n
             |  Returns:     |  a list with the files transfered                                                                                  |
        '''

        time.sleep(float(timeout))

        com="/usr/bin/glite-ce-job-output -N -D %s %s" % (dest_dir,job_id)
        args = shlex.split(com.encode('ascii'))
        p = subprocess.Popen( args , shell=False , stderr=subprocess.STDOUT , stdout=subprocess.PIPE )
	fPtr=p.stdout

        retVal=p.wait()

        output=fPtr.readlines()

	if retVal != 0:
		raise _error("Output file transfer failed with return value: " + str(p.returncode) + " \nCommand reported: " +  ','.join(output) )
                #kinda rough output creation,maybe should find a better one

        cream_output_dir=os.listdir(dest_dir)[0]

        #return a list with the files downloaded with the glite-ce-job-output command,in the folder output_dir_name.
        files_transfered_on_disk = os.listdir(dest_dir + "/" + cream_output_dir )

        #copy to an easier to use place (dest_dir which is fixed,instead of the variable cream output dir)
        
        for file in files_transfered_on_disk:
                os.rename(dest_dir+"/"+cream_output_dir+"/"+file,dest_dir+"/"+file)
        #print files_transfered_on_disk

        return files_transfered_on_disk
##############################################################################################################################
##############################################################################################################################
def list_jobs(ce_endpoint):
        '''
                |  Description:  |  List the jobs not purged by the specified cream endpoint for the user executing the command. | \n
                |  Arguments:    |  ce_endpoint   |  cream endpoint.                                                             | \n
                |  Returns:      |  a list containing all the relevant job ids                                                   |
        '''

        com="/usr/bin/glite-ce-job-list %s" % ce_endpoint
        args = shlex.split(com.encode('ascii'))
        p = subprocess.Popen( args , shell=False , stderr=subprocess.STDOUT , stdout=subprocess.PIPE )
	fPtr=p.stdout

        retVal=p.wait()

        output=fPtr.readlines()

	if retVal != 0:
		raise _error("Job list failed with return value: " + str(p.returncode) + " \nCommand reported: " +  ','.join(output) )
                #kinda rough output creation,maybe should find a better one

        output = map(string.strip, output)

        return output
##############################################################################################################################
##############################################################################################################################
def cancel_job(job_id):
        '''
                |  Description:  |  Cancel the given job.                                       | \n
                |  Arguments:    |  job_id     |    as returned by the submit operation.        | \n
                |  Returns:      |  nothing.                                                    |
        '''

        com="/usr/bin/glite-ce-job-cancel -d -N %s" % job_id
        args = shlex.split(com.encode('ascii'))
        p = subprocess.Popen( args , shell=False , stderr=subprocess.STDOUT , stdout=subprocess.PIPE )
	fPtr=p.stdout

        retVal=p.wait()

        output=fPtr.read()

        print 'Command "' + com + '" output follows:'
        print output

        if "error" in output.lower() or "fatal" in output.lower() or "fault" in output.lower() or retVal != 0 :
		raise _error("Job cancel operation failed with return value: " + str(p.returncode) + " \nCommand reported: " +  output )
##############################################################################################################################
##############################################################################################################################
def destroy_proxy():
        '''
                |  Description:  |  Delete a user's proxy.  | \n
                |  Arguments:    |  none.                   | \n
                |  Returns:      |  nothing.                |
        '''

        com="/usr/bin/voms-proxy-destroy"
        args = shlex.split(com.encode('ascii'))
        p = subprocess.Popen( args , shell=False , stderr=subprocess.STDOUT , stdout=subprocess.PIPE )
        fPtr=p.stdout

        retVal=p.wait()

        output=fPtr.readlines()

        if retVal != 0 :
		raise _error("Proxy destroy operation failed with return value: " + str(p.returncode) + " \nCommand reported: " +  ','.join(output) )
##############################################################################################################################
##############################################################################################################################
def suspend_job(job_id):
        '''
                |  Description:  |  Suspends the given job.                                     | \n
                |  Arguments:    |  job id     |    as returned by the submit operation.        | \n
                |  Returns:      |  nothing.                                                    |
        '''

        com="/usr/bin/glite-ce-job-suspend -N %s" % job_id
        args = shlex.split(com.encode('ascii'))
        p = subprocess.Popen( args , shell=False , stderr=subprocess.STDOUT , stdout=subprocess.PIPE )
	fPtr=p.stdout

        retVal=p.wait()

        output=fPtr.readlines()

        if "error" in ','.join(output).lower() or "fatal" in ','.join(output).lower() or "fault" in ','.join(output).lower() or retVal != 0 :
		raise _error("Job suspend operation failed with return value: " + str(p.returncode) + " \nCommand reported: " +  ','.join(output) )
                #kinda rough output creation,maybe should find a better one
##############################################################################################################################
##############################################################################################################################
def resume_job(job_id):
        '''
                |  Description:  |  Resumes the given (previously suspended) job.            | \n
                |  Arguments:    |  job id      |    as returned by the submit operation.    | \n
                |  Returns:      |  nothing.                                                 |
        '''

        com="/usr/bin/glite-ce-job-resume -N %s" % job_id
        args = shlex.split(com.encode('ascii'))
        p = subprocess.Popen( args , shell=False , stderr=subprocess.STDOUT , stdout=subprocess.PIPE )
	fPtr=p.stdout

        retVal=p.wait()

        output=fPtr.readlines()

        if "error" in ','.join(output).lower() or "fatal" in ','.join(output).lower() or "fault" in ','.join(output).lower() or retVal != 0 :
		raise _error("Job suspend operation failed with return value: " + str(p.returncode) + " \nCommand reported: " +  ','.join(output) )
                #kinda rough output creation,maybe should find a better one
##############################################################################################################################
##############################################################################################################################
def cancel_all_jobs(ce_endpoint):
        '''
                |  Description:  |  Cancel all the user's jobs in the given cream endpoint. | \n
                |  Arguments:    |  ce_endpoint   |  cream endpoint.                        | \n
                |  Returns:      |  nothing.                                                |
        '''

        com="/usr/bin/glite-ce-job-cancel -N -a -e %s" % ce_endpoint
        args = shlex.split(com.encode('ascii'))
        p = subprocess.Popen( args , shell=False , stderr=subprocess.STDOUT , stdout=subprocess.PIPE )
	fPtr=p.stdout

        retVal=p.wait()

        output=fPtr.readlines()

        if "error" in ','.join(output).lower() or "fatal" in ','.join(output).lower() or "fault" in ','.join(output).lower() or retVal != 0 :
		raise _error("Job all-cancel operation failed with return value: " + str(p.returncode) + " \nCommand reported: " +  ','.join(output) )
                #kinda rough output creation,maybe should find a better one
##############################################################################################################################
##############################################################################################################################
def purge_all_jobs(ce_endpoint):
        '''
                |  Description:  |  Purge all the user's jobs in the given cream endpoint.  | \n
                |  Arguments:    |  ce_endpoint   |  cream endpoint.                        | \n
                |  Returns:      |  nothing.                                                |
        '''

        com="/usr/bin/glite-ce-job-purge -N -a -e %s" % ce_endpoint
        args = shlex.split(com.encode('ascii'))
        p = subprocess.Popen( args , shell=False , stderr=subprocess.STDOUT , stdout=subprocess.PIPE )
	fPtr=p.stdout

        retVal=p.wait()

        output=fPtr.readlines()

        if "error" in ','.join(output).lower() or "fatal" in ','.join(output).lower() or "fault" in ','.join(output).lower() or retVal != 0 :
		raise _error("Job all-purge operation failed with return value: " + str(p.returncode) + " \nCommand reported: " +  ','.join(output) )
                #kinda rough output creation,maybe should find a better one
##############################################################################################################################
##############################################################################################################################
def suspend_all_jobs(ce_endpoint):
        '''
                |  Description:  |  Suspend all the user's jobs in the given cream endpoint.    | \n
                |  Arguments:    |  ce_endpoint   |  cream endpoint.                            | \n
                |  Returns:      |  nothing.                                                    |
        '''

        com="/usr/bin/glite-ce-job-suspend -N -a -e %s" % ce_endpoint
        args = shlex.split(com.encode('ascii'))
        p = subprocess.Popen( args , shell=False , stderr=subprocess.STDOUT , stdout=subprocess.PIPE )
	fPtr=p.stdout

        retVal=p.wait()

        output=fPtr.readlines()

        if "error" in ','.join(output).lower() or "fatal" in ','.join(output).lower() or "fault" in ','.join(output).lower() or retVal != 0 :
		raise _error("Job all-suspend operation failed with return value: " + str(p.returncode) + " \nCommand reported: " +  ','.join(output) )
                #kinda rough output creation,maybe should find a better one
##############################################################################################################################
##############################################################################################################################
def resume_all_jobs(ce_endpoint):
        '''
                |  Description:  |  Suspend all the user's jobs in the given cream endpoint.    | \n
                |  Arguments:    |  ce_endpoint   |  cream endpoint.                            | \n
                |  Returns:      |  nothing.                                                    |
        '''

        com="/usr/bin/glite-ce-job-resume -N -a -e %s" % ce_endpoint
        args = shlex.split(com.encode('ascii'))
        p = subprocess.Popen( args , shell=False , stderr=subprocess.STDOUT , stdout=subprocess.PIPE )
	fPtr=p.stdout

        retVal=p.wait()

        output=fPtr.readlines()

        if "error" in ','.join(output).lower() or "fatal" in ','.join(output).lower() or "fault" in ','.join(output).lower() or retVal != 0 :
		raise _error("Job all-resume operation failed with return value: " + str(p.returncode) + " \nCommand reported: " +  ','.join(output) )
                #kinda rough output creation,maybe should find a better one
##############################################################################################################################
##############################################################################################################################
def submit_and_wait(jdl_path=None,ce_endpoint=None,delegId=None):
        '''
                |  Description:   |  Submit a job and wait until it finishes.  | \n
                |  Arguments:     |  Same as submit_job.                       | \n
                |  Returns:       |  (int,string) as jid and final job state.  | \n
        '''

        jid=submit_job(jdl_path,ce_endpoint,delegId)
        final_status=get_final_status(jid)
        return (jid,final_status)
##############################################################################################################################
##############################################################################################################################
def get_current_status_verbose(job_id):
        '''
                |  Description:  |  Return the current status of a job,with the use of the glite-ce-job-status command,with verbosity level 2. |
                |                |  This function will NOT wait until the job is in a final state.                                             | \n
                |  Arguments:    |  job_id      |    as returned by the submit operation.                                                      | \n
                |  Returns:      |  a string.                                                                                                  |
        '''

        running_states = ['IDLE','REGISTERED', 'PENDING', 'RUNNING', 'REALLY-RUNNING', 'HELD']
        final_states = ['DONE-OK', 'DONE-FAILED', 'ABORTED', 'CANCELLED']

        com="glite-ce-job-status -L 2 " + job_id
        args = shlex.split(com.encode('ascii'))

        p = subprocess.Popen( args , stderr=subprocess.STDOUT , stdout=subprocess.PIPE )
        fPtr=p.stdout

        output=fPtr.read()

        p.wait()

        if p.returncode != 0 or ("FaultCause" in output and "ErrorCode" in output):
                raise _error("Job status polling failed with return value: " + str(p.returncode) + "\nCommand reported: " + output)

        #print output

        return output
##############################################################################################################################
##############################################################################################################################
def check_osb_basedesturi_files(jdl_path, gridftp_server, gridftp_path):
        '''
                |  Description:  |   Read from a jdl file the list of files contained in the OutputSandBox and OutputSandboxBaseDestURI attribute. |
                |                |   Then check if these files exist or not.                                                                       | \n
                |  Arguments:    |   jdl_path            |    path to the jdl file                                                                 |
                |                |   gridftp_server      |    the gridftp server in use                                                            |
                |                |   gridftp_path        |    the path within the gridftp server                                                   | \n
                |  Returns:      |   True or False.                                                                                                |
        '''

        osb_list=get_osb(jdl_path)
        #print osb_list

        #read jdl file as string
        jdl_as_string=open(jdl_path).read()

        #replace various indifferent syntactic variaties with a certain one,to make string matching easier
        copy1=jdl_as_string.replace(" = ","=")
        copy2=copy1.replace(" =","=")
        copy3=copy2.replace("= ","=")
        copy4=copy3.lower() #NOTE: is this dangerous?should case sensitivity be kept or not?does it matter?

        #search for the position of the OutputSandboxBaseDestURI
        pos = copy4.find("outputsandboxbasedesturi=")
        if pos == -1:
                raise _error("OutputSandboxBaseDestURI attribute not found!")

        #print "pos= " + str(pos)

        #get a copy of the string starting where the part that interests us is
        copy5 = copy4[pos:]

        #print "final copy= " + copy5

        #extract the attribute value,between the two double quotes
        base_dest_uri = copy5[copy5.find('"')+1:copy5.find(';')-1]

        #print "base dest uri= " + base_dest_uri


        gridftp_server_file_list = execute_uberftp_command("ls", gridftp_server, gridftp_path)
        for file in osb_list:
                print "Checking existence of file: " + file
                if file not in gridftp_server_file_list:
                        print 'File "' + file + '" not found!'
                        return False

        return True
##############################################################################################################################
##############################################################################################################################
def delete_osb_basedesturi_files(jdl_path, gridftp_server, gridftp_path):
        '''
                |  Description:  |   Read from a jdl file the list of files contained in the OutputSandBox and OutputSandboxBaseDestURI attribute. |
                |                |   Then delete these files with lcg-del.                                                                         | \n
                |  Arguments:    |   jdl_path            |    path to the jdl file                                                                 |
                |                |   gridftp_server      |    the gridftp server in use                                                            |
                |                |   gridftp_path        |    the path within the gridftp server                                                   | \n
                |  Returns:      |   nothing.                                                                                                      |
        '''

        osb_list=get_osb(jdl_path)
        #print osb_list

        #read jdl file as string
        jdl_as_string=open(jdl_path).read()

        #replace various indifferent syntactic variaties with a certain one,to make string matching easier
        copy1=jdl_as_string.replace(" = ","=")
        copy2=copy1.replace(" =","=")
        copy3=copy2.replace("= ","=")
        copy4=copy3.lower() #NOTE: is this dangerous?should case sensitivity be kept or not?does it matter?

        #search for the position of the OutputSandboxBaseDestURI
        pos = copy4.find("outputsandboxbasedesturi=")
        if pos == -1:
                raise _error("OutputSandboxBaseDestURI attribute not found!")

        #print "pos= " + str(pos)

        #get a copy of the string starting where the part that interests us is
        copy5 = copy4[pos:]

        #print "final copy= " + copy5

        #extract the attribute value,between the two double quotes
        base_dest_uri = copy5[copy5.find('"')+1:copy5.find(';')-1]

        #print "base dest uri= " + base_dest_uri

        for file in osb_list:
                print "Deleting file: gsiftp://" + gridftp_server + gridftp_path + '/' + file
                execute_uberftp_command("rm", gridftp_server, gridftp_path+'/'+file)
##############################################################################################################################
##############################################################################################################################
def check_osb_desturi_files(jdl_path, gridftp_server, gridftp_path):
        '''
                |  Description:  |  Read from a jdl file the list of files contained in the OutputSandboxDestURI attribute.     |
                |                |  Then check if these files exist or not.                                                     | \n
                |  Arguments:    |  jdl_path           |     path to the jdl file                                               |
                |                |  gridftp_server     |     the gridftp server in use                                          |
                |                |  gridftp_path       |     the path within the gridftp server                                 | \n
                |  Returns:      |  True or False.                                                                              |
        '''

        #read jdl file as string
        jdl_as_string=open(jdl_path).read()

        #replace various indifferent syntactic variaties with a certain one,to make string matching easier
        copy1=jdl_as_string.replace(" = ","=")
        copy2=copy1.replace(" =","=")
        copy3=copy2.replace("= ","=")
        copy4=copy3.lower() #NOTE: is this dangerous?should case sensitivity be kept or not?does it matter?

        #search for the position of the OutputSandboxBaseDestURI
        pos = copy4.find("outputsandboxdesturi=")
        if pos == -1:
                raise _error("OutputSandboxDestURI attribute not found!")

        #print "pos= " + str(pos)

        #get a copy of the string starting where the part that interests us is
        copy5 = copy4[pos:]

        #print "final copy= " + copy5

        #extract the file list,between the two braces
        jdl_file_list = copy5[copy5.find("{")+1:copy5.find("}")]

        #extract substrings within quotes (which should be the files in the output sandbox)
        #python extended slicing used,meaning: start at element 1 (1:),finish at the end(::),read every 2 elements (:2).
        file_list=jdl_file_list.split('"')[1::2]

        #print file_list

        #print "base dest uri= " + base_dest_uri

        for file in file_list:
                print "Checking existence of file: " + file

                #file path is in the form: gsiftp://se01.isabella.grnet.gr/tmp/job2.out
                #so it must be broken down and reconstructed to be ginen to execut_uberftp_command()
                file_path = '/'
                for item in file.split('/')[3:]:
                        file_path += item
                        file_path += '/'

                #delete trailing '/' -which I intentionally put there,for code simplicity in the above lines
                file_path = file_path[:-1]

                # Execute_uberftp_command raises exception on an error. So if an invalid path is given,it will raise it.
                # So in order to return false instead of raising the exception (and since here I check against possibly
                # invalid paths) the exception is caught and processed.
                # This methodology isn't generally used in this module.
                try:
                        execute_uberftp_command("ls", gridftp_server, file_path)
                except Exception as ex:
                        if "No match for" in ex.string:
                                return False

        return True
##############################################################################################################################
##############################################################################################################################
def delete_osb_desturi_files(jdl_path, gridftp_server):
        '''
                |  Description:  |  Read from a jdl file the list of files contained in the OutputSandboxDestURI attribute.     |
                |                |  Then delete these files with lcg-del.                                                       | \n
                |  Arguments:    |  jdl_path         |       path to the jdl file                                               |
                |                |  gridftp_server   |       the gridftp server in use                                          | \n
                |  Returns:      |  nothing.                                                                                    |
        '''

        #read jdl file as string
        jdl_as_string=open(jdl_path).read()

        #replace various indifferent syntactic variaties with a certain one,to make string matching easier
        copy1=jdl_as_string.replace(" = ","=")
        copy2=copy1.replace(" =","=")
        copy3=copy2.replace("= ","=")
        copy4=copy3.lower() #NOTE: is this dangerous?should case sensitivity be kept or not?does it matter?

        #search for the position of the OutputSandboxBaseDestURI
        pos = copy4.find("outputsandboxdesturi=")
        if pos == -1:
                raise _error("OutputSandboxDestURI attribute not found!" + "\n" + jdl_as_strings )

        #print "pos= " + str(pos)

        #get a copy of the string starting where the part that interests us is
        copy5 = copy4[pos:]

        #print "final copy= " + copy5

        #extract the file list,between the two braces
        jdl_file_list = copy5[copy5.find("{")+1:copy5.find("}")]

        #extract substrings within quotes (which should be the files in the output sandbox)
        #python extended slicing used,meaning: start at element 1 (1:),finish at the end(::),read every 2 elements (:2).
        file_list=jdl_file_list.split('"')[1::2]

        #print file_list

        for file in file_list:
                print "Deleting file: " + file

                #file path is in the form: gsiftp://se01.isabella.grnet.gr/tmp/job2.out
                #so it must be broken down and reconstructed to be ginen to execut_uberftp_command()
                file_path = '/'
                for item in file.split('/')[3:]:
                        file_path += item
                        file_path += '/'

                #delete trailing '/' -which I intentionally put there,for code simplicity in the above lines
                file_path = file_path[:-1]

                execute_uberftp_command("rm", gridftp_server, file_path)
##############################################################################################################################
##############################################################################################################################
def file_should_contain(file_path,search_string):
        '''
                |  Description:  |  Check whether the given file contains the given string.                             |
                |                |  Note that this must be used for small files,since it reads it all in memory.        | \n
                |  Arguments:    |  file_path           |    the path pointing to the file                              |
                |                |  search_string       |    the string searching for                                   | \n
                |  Returns:      |  True or False.                                                                      |
        '''

        #converting to ascii since robot framework sends unicode strings,which generally cause various problems
        file_path=file_path.encode('ascii')
        search_string=search_string.encode('ascii')

        file_as_string=open(file_path).read()
        if search_string in file_as_string:
                return True

        return False
##############################################################################################################################
##############################################################################################################################
def destroy_delegation(deleg_endpoint,deleg_id):
        '''
                |  Description:  |  Delete a delegation.                                                        | \ns
                |  Arguments:    |  deleg_endpoint    |     the delegation endpoint of a cream service          |
                |                |  deleg_id          |     the delegation id                                   | \n
                |  Returns:      |  nothing.                                                                    |
        '''

        com="/usr/bin/glite-delegation-destroy -s " + deleg_endpoint + " " + deleg_id
        args = shlex.split(com.encode('ascii'))
        p = subprocess.Popen( args , shell=False , stderr=subprocess.STDOUT , stdout=subprocess.PIPE )
        fPtr=p.stdout

        retVal=p.wait()

        output=fPtr.readlines()

        #if retVal != 0 :
        if "error" in ','.join(output) or "fault" in ','.join(output) or retVal != 0 :
		raise _error("Delegation destroy failed with return value: " + str(p.returncode) + " \nCommand reported: " +  ','.join(output) )
##############################################################################################################################
##############################################################################################################################


'''
                        DATA MANIPULATION METHODS
To test them,run the following commands in a python shell (modify target dirs,se,vo etc as needed) :
import cream_testing as w
w.create_proxy('q1w2e3r4','see')
w.lfc_mkdir('/grid/see/aek_ole')
w.lcg_cr('see','/home/dfiore/cream/my_python_tests/cream_testing.py','se01.isabella.grnet.gr','/grid/see/aek_ole/aek.py')
w.lfc_ls('/grid/see/aek_ole')
w.lcg_cp('see','/grid/see/aek_ole/aek.py','/tmp/ole.py')
w.lcg_del('see','/grid/see/aek_ole/aek.py')
w.lfc_rmdir('/grid/see/aek_ole')
w.lfc_ls('/grid/see/aek_ole')
w.destroy_proxy()

'''
##############################################################################################################################
##############################################################################################################################
def lfc_ls(lfn_path):
        '''
                |  Description:  |  List an lfn,using lfc-ls.           | \n
                |  Arguments:    |  lfn_path    |   imaginary lfc path  | \n
                |  Returns:      |  List containing all the files.      |
        '''

        com="/usr/bin/lfc-ls " + lfn_path
        args = shlex.split(com.encode('ascii'))
        p = subprocess.Popen( args , shell=False , stderr=subprocess.STDOUT , stdout=subprocess.PIPE )
        fPtr=p.stdout

        retVal=p.wait()

        output=fPtr.readlines()

        # if there isn't any such file or directory,just return the empty list,not an error!
        for line in output:
                if 'No such file or directory' in line:
                        output=[]
                        return output

        if retVal != 0:
		raise _error("lfc-ls operation failed with return value: " + str(p.returncode) + " \nCommand reported: " +  ','.join(output) )

        return output
##############################################################################################################################
##############################################################################################################################
def lcg_cr(vo,local_fname,storage_element,lfn):
        '''
                |  Description:  |  Upload a file to an SE,using lcg-cr.                        | \n
                |  Arguments:    |  vo                  |   virtual organisation                |
                |                |  local_fname         |   local file's name to upload         |
                |                |  storage_element     |   storage element to be used          |
                |                |  lfn                 |   the logical file name to use        | \n
                |  Returns:      |  Nothing.                                                    |
        '''

        com="/usr/bin/lcg-cr --vo " + vo + " -d " + storage_element + " -l " + lfn + " file:" + local_fname
        args = shlex.split(com.encode('ascii'))
        p = subprocess.Popen( args , shell=False , stderr=subprocess.STDOUT , stdout=subprocess.PIPE )
        fPtr=p.stdout

        retVal=p.wait()

        output=fPtr.readlines()

        if retVal != 0 :
		raise _error("lcg-cr operation failed with return value: " + str(p.returncode) + " \nCommand reported: " +  ','.join(output) )
##############################################################################################################################
##############################################################################################################################
def lcg_del(vo,lfn):
        '''
                |  Description:  |  Delete all replicas of a file and its LFC entry,using lcg-del.      | \n
                |  Arguments:    |  vo      |  virtual organisation                                     |
                |                |  lfn     |  logical file name to delete                              | \n
                |  Returns:      |  Nothing.                                                            |
        '''

        com="/usr/bin/lcg-del --vo " + vo + " -a lfn:" + lfn
        args = shlex.split(com.encode('ascii'))
        p = subprocess.Popen( args , shell=False , stderr=subprocess.STDOUT , stdout=subprocess.PIPE )
        fPtr=p.stdout

        retVal=p.wait()

        output=fPtr.readlines()

        if retVal != 0 :
		raise _error("lcg-del operation failed with return value: " + str(p.returncode) + " \nCommand reported: " +  ','.join(output) )
##############################################################################################################################
##############################################################################################################################
def lcg_cp(vo,lfn,local_fname):
        '''
                |  Description:  |  Copy a file from an SE to localhost,using lcg-cp.   | \n
                |  Arguments:    |  vo           |    virtual organisation              |
                |                |  lfn          |    logical file name to download     |
                |                |  local_fname  |    local file name to use            | \n
                |  Returns:      |  Nothing.                                            |
        '''

        com="/usr/bin/lcg-cp --vo " + vo + " lfn:" + lfn + " file:" + local_fname
        args = shlex.split(com.encode('ascii'))
        p = subprocess.Popen( args , shell=False , stderr=subprocess.STDOUT , stdout=subprocess.PIPE )
        fPtr=p.stdout

        retVal=p.wait()

        output=fPtr.readlines()

        if retVal != 0 :
		raise _error("lcg-cp operation failed with return value: " + str(p.returncode) + " \nCommand reported: " +  ','.join(output) )
##############################################################################################################################
##############################################################################################################################
def lfc_mkdir(lfn_path):
        '''
                |  Description:  |  Create a folder in the LFC,using lfc-mkdir. | \n
                |  Arguments:    |  lfn_path    |   imaginary lfc path          | \n
                |  Returns:      |  Nothing.                                    |
        '''

        com="/usr/bin/lfc-mkdir " + lfn_path
        args = shlex.split(com.encode('ascii'))
        p = subprocess.Popen( args , shell=False , stderr=subprocess.STDOUT , stdout=subprocess.PIPE )
        fPtr=p.stdout

        retVal=p.wait()

        output=fPtr.readlines()

        if retVal != 0 :
		raise _error("lfc-mkdir operation failed with return value: " + str(p.returncode) + " \nCommand reported: " +  ','.join(output) )
##############################################################################################################################
##############################################################################################################################
def lfc_rmdir(lfn_path):
        '''
                |  Description:  |  Delete a folder in the LFC,using lfc-rm -r. | \n
                |  Arguments:    |  lfn_path    |    imaginary lfc path         | \n
                |  Returns:      |  Nothing.                                    |
        '''

        com="/usr/bin/lfc-rm -r " + lfn_path
        args = shlex.split(com.encode('ascii'))
        p = subprocess.Popen( args , shell=False , stderr=subprocess.STDOUT , stdout=subprocess.PIPE )
        fPtr=p.stdout

        retVal=p.wait()

        output=fPtr.readlines()

        if retVal != 0 :
		raise _error("lfc-rm -r operation failed with return value: " + str(p.returncode) + " \nCommand reported: " +  ','.join(output) )
##############################################################################################################################
##############################################################################################################################

'''
                        JDL CREATION METHODS
To test them,uncomment the following method and run it in a python shell. The vo and cream endpoint variables should probably
change to ones valid under the testing environment.
(note: data manipulation jdls are not tested by this,due to their greater complexity,but if these jdls are submitted and
executed correctly,it is highly improbable for the others not to work.)

def test_jdls():
        l = []
        l.append(simple_jdl('dteam'))
        l.append(sleep_jdl('dteam',10))
        l.append(cpunumber_jdl('dteam',1))
        l.append(hostnumber_jdl('dteam',1))
        l.append(wholenodes_jdl('dteam','False'))
        l.append(smpgranularity_jdl('dteam',1))
        l.append(combo_jdl('dteam','True',1,2))
        l.append(localhost_output_jdl('dteam'))
        l.append(environment_jdl('dteam')[0])
        l.append(isb_client_to_ce_jdl('dteam')[0])
        l.append(prologue_jdl('dteam')[0])
        l.append(epilogue_jdl('dteam')[0])

        for i in l:
                print "Submitting " + i
                result = submit_and_wait(i,"cream-38.pd.infn.it:8443/cream-pbs-creamtest1")
                print "Got " + result[0] + " " + result[1]


'''
##############################################################################################################################
##############################################################################################################################
def simple_jdl(vo, output_dir):
        '''
                |  Description:  |  Simple jdl file.Executes /bin/uname -a.             | \n
                |  Arguments:    |  vo           |   virtual organisation               |
                |                |  output_dir   |   the directory to put the file in   | \n
                |  Returns:      |  Temporary file name.                                |
        '''

        folder = output_dir
        identifier = 'simple'
        name = 'cream_testing-' + str(time.time()) + '-' + identifier + '.jdl'
        path = folder + '/' + name

        jdl_file = open(path,'w')

        jdl_contents =  '[\n'\
                        'Type="job";\n'\
                        'JobType="normal";\n'\
                        'VirtualOrganisation="' + vo + '";\n'\
                        'Executable="/bin/uname";\n'\
                        'Arguments="-a";\n'\
                        'StdOutput="job.out";\n'\
                        'StdError="job.err";\n'\
                        ']\n'


        jdl_file.write(jdl_contents)
        jdl_file.close()

        return path
##############################################################################################################################
##############################################################################################################################
def sleep_jdl(vo,secs, output_dir):
        '''
                |  Description: |   Simple jdl file.Executes /bin/sleep for the defined number of seconds.      | \n
                |  Arguments:   |   vo           |   virtual organisation                                       |
                |               |   secs         |   seconds to sleep                                           |
                |               |   output_dir   |   the directory to put the file in                           | \n
                |  Returns:     |   Temporary file name.                                                        |
        '''

        folder = output_dir
        identifier = 'sleep'
        name = 'cream_testing-' + str(time.time()) + '-' + identifier + '.jdl'
        path = folder + '/' + name

        jdl_file = open(path,'w')

        jdl_contents =  '[\n'\
                        'Type="job";\n'\
                        'JobType="normal";\n'\
                        'VirtualOrganisation="' + vo + '";\n'\
                        'Executable="/bin/sleep";\n'\
                        'Arguments="' + str(secs) + '";\n'\
                        'StdOutput="job.out";\n'\
                        'StdError="job.err";\n'\
                        ']\n'


        jdl_file.write(jdl_contents)
        jdl_file.close()

        return path
##############################################################################################################################
##############################################################################################################################
def cpunumber_jdl(vo,cpunumber, output_dir):
        '''
                |  Description:  |   Attribute checking jdl file.Sets the jdl attribute "CPUNumber" to the given number.        | \n
                |  Arguments:    |   vo           |   virtual organisation                                                      |
                |                |   cpunumber    |   jdl attribute                                                             |
                |                |   output_dir   |   the directory to put the file in                                          | \n
                |  Returns:      |   Temporary file name.                                                                       |
        '''

        folder = output_dir
        identifier = 'cpunumber'
        name = 'cream_testing-' + str(time.time()) + '-' + identifier + '.jdl'
        path = folder + '/' + name

        jdl_file = open(path,'w')

        jdl_contents =  '[\n'\
                        'Type="job";\n'\
                        'JobType="normal";\n'\
                        'VirtualOrganisation="' + vo + '";\n'\
                        'Executable="/bin/uname";\n'\
                        'Arguments="-a";\n'\
                        'CPUNumber=' + str(cpunumber) + ';\n'\
                        'StdOutput="job.out";\n'\
                        'StdError="job.err";\n'\
                        ']\n'


        jdl_file.write(jdl_contents)
        jdl_file.close()

        return path
##############################################################################################################################
##############################################################################################################################
def hostnumber_jdl(vo, hostnumber, output_dir):
        '''
                |  Description:  |  Attribute checking jdl file.Sets the jdl attribute "HostNumber" to the given number.        | \n
                |  Arguments:    |  vo           |   virtual organisation                                                       |
                |                |  hostnumber   |   jdl attribute                                                              |
                |                |  output_dir   |   the directory to put the file in                                           | \n
                |  Returns:      |  Temporary file name.                                                                        |
        '''

        folder = output_dir
        identifier = 'hostnumber'
        name = 'cream_testing-' + str(time.time()) + '-' + identifier + '.jdl'
        path = folder + '/' + name

        jdl_file = open(path,'w')

        jdl_contents =  '[\n'\
                        'Type="job";\n'\
                        'JobType="normal";\n'\
                        'VirtualOrganisation="' + vo + '";\n'\
                        'Executable="/bin/uname";\n'\
                        'Arguments="-a";\n'\
                        'HostNumber=' + str(hostnumber) + ';\n'\
                        'StdOutput="job.out";\n'\
                        'StdError="job.err";\n'\
                        ']\n'


        jdl_file.write(jdl_contents)
        jdl_file.close()

        return path
##############################################################################################################################
##############################################################################################################################
def wholenodes_jdl(vo, wholenodes, output_dir):
        '''
                |  Description:  |  Attribute checking jdl file.Sets the jdl attribute "WholeNodes" to the given value. | \n
                |  Arguments:    |  vo              virtual organisation                                                |
                |                |  wholenodes      jdl attribute                                                       |
                |                |  output_dir      the directory to put the file in                                    | \n
                |  Returns:      |  Temporary file name.                                                                |
        '''

        folder = output_dir
        identifier = 'wholenodes'
        name = 'cream_testing-' + str(time.time()) + '-' + identifier + '.jdl'
        path = folder + '/' + name

        jdl_file = open(path,'w')

        jdl_contents =  '[\n'\
                        'Type="job";\n'\
                        'JobType="normal";\n'\
                        'VirtualOrganisation="' + vo + '";\n'\
                        'Executable="/bin/uname";\n'\
                        'Arguments="-a";\n'\
                        'WholeNodes=' + wholenodes + ';\n'\
                        'StdOutput="job.out";\n'\
                        'StdError="job.err";\n'\
                        ']\n'


        jdl_file.write(jdl_contents)
        jdl_file.close()

        return path
##############################################################################################################################
##############################################################################################################################
def smpgranularity_jdl(vo, smpgranularity, output_dir):
        '''
                |  Description:  |   Attribute checking jdl file.Sets the jdl attribute "SMPGranularity" to the given number.   | \n
                |  Arguments:    |   vo              |  virtual organisation                                                    |
                |                |   smpgranularity  |  jdl attribute                                                           |
                |                |   output_dir      |  the directory to put the file in                                        | \n
                |  Returns:      |   Temporary file name.                                                                       |
        '''

        folder = output_dir
        identifier = 'smpgranularity'
        name = 'cream_testing-' + str(time.time()) + '-' + identifier + '.jdl'
        path = folder + '/' + name

        jdl_file = open(path,'w')

        jdl_contents =  '[\n'\
                        'Type="job";\n'\
                        'JobType="normal";\n'\
                        'VirtualOrganisation="' + vo + '";\n'\
                        'Executable="/bin/uname";\n'\
                        'Arguments="-a";\n'\
                        'SMPGranularity=' + str(smpgranularity) + ';\n'\
                        'StdOutput="job.out";\n'\
                        'StdError="job.err";\n'\
                        ']\n'


        jdl_file.write(jdl_contents)
        jdl_file.close()

        return path
##############################################################################################################################
##############################################################################################################################
def combo_jdl(vo, wholenodes, hostnumber, smpgranularity, output_dir):
        '''
                |  Description:  |  Attribute checking jdl file.Sets the jdl attributes "WholeNodes","HostNumber" and "SMPGranularity"          |
                |                |  to the given numbers/values. It is used to test whether these attributes can be combined. In theory,        |
                |                |  when WholeNodes is "False",the other two shouldn't be able to be set and an error should be produced        |
                |                |  during jdl submission. This should be tested for arbitrary values of hostnumber and smpgranularity,         |
                |                |  and for both cases of wholenodes (set to "True" and set to "False").                                        | \n
                |  Arguments:    |  vo              |  virtual organisation                                                                     |
                |                |  smpgranularity  |  jdl attribute                                                                            |
                |                |  hostnumber      |  jdl attribute                                                                            |
                |                |  wholenodes      |  jdl attribute                                                                            |
                |                |  output_dir      |  the directory to put the file in                                                         |
                |  Returns:      |  Temporary file name.                                                                                        |
        '''

        folder = output_dir
        identifier = 'combo'
        name = 'cream_testing-' + str(time.time()) + '-' + identifier + '.jdl'
        path = folder + '/' + name

        jdl_file = open(path,'w')

        jdl_contents =  '[\n'\
                        'Type="job";\n'\
                        'JobType="normal";\n'\
                        'VirtualOrganisation="' + vo + '";\n'\
                        'Executable="/bin/uname";\n'\
                        'Arguments="-a";\n'\
                        'SMPGranularity=' + str(smpgranularity) + ';\n'\
                        'HostNumber=' + str(hostnumber) + ';\n'\
                        'WholeNodes=' + wholenodes + ';\n'\
                        'StdOutput="job.out";\n'\
                        'StdError="job.err";\n'\
                        ']\n'


        jdl_file.write(jdl_contents)
        jdl_file.close()

        return path
##############################################################################################################################
##############################################################################################################################
def localhost_output_jdl(vo, output_dir):
        '''
                |  Description:  |  File transfer checking jdl file. Stage files to the CE node (gsiftp://localhost).   | \n
                |  Arguments:    |  vo           |   virtual organisation                                               |
                |                |  output_dir   |   the directory to put the file in                                   | \n
                |  Returns:      |  Temporary file name.                                                                |
        '''

        folder = output_dir
        identifier = 'localhost_output'
        name = 'cream_testing-' + str(time.time()) + '-' + identifier + '.jdl'
        path = folder + '/' + name

        jdl_file = open(path,'w')

        jdl_contents =  '[\n'\
                        'Type="job";\n'\
                        'JobType="normal";\n'\
                        'VirtualOrganisation="' + vo + '";\n'\
                        'Executable="/bin/uname";\n'\
                        'Arguments="-a";\n'\
                        'StdOutput="job.out";\n'\
                        'StdError="job.err";\n'\
                        'OutputSandbox={\n'\
                        '                       "job.out",\n'\
                        '                       "job.err"\n'\
                        '               };\n'\
                        'OutputSandboxBaseDestURI="gsiftp://localhost";\n'\
                        ']\n'


        jdl_file.write(jdl_contents)
        jdl_file.close()

        return path
##############################################################################################################################
##############################################################################################################################
def environment_jdl(vo, output_dir):
        '''
                |  Description:  |   Attribute checking jdl file. Set an environmental variable and check its value during runtime.     | \n
                |  Arguments:    |   vo           |   virtual organisation                                                              |
                |                |   output_dir   |   the directory to put the file in                                                  | \n
                |  Returns:      |   Temporary jdl file name,temporary shell script file name.                                          |
        '''

        folder = output_dir

        jdl_identifier = 'environment'
        jdl_name = 'cream_testing-' + str(time.time()) + '-' + jdl_identifier + '.jdl'
        jdl_path = folder + '/' + jdl_name

        script_identifier = 'environment'
        script_name = 'cream_testing-' + str(time.time()) + '-' + script_identifier + '.sh'
        script_path = folder + '/' + script_name

        script_file = open(script_path,'w')

        script_contents =       '#!/bin/bash\n'\
                                '\n'\
                                'echo "ENV_VAR=$ENV_VAR"\n'\
                                '\n'\
                                'exit $?\n'

        script_file.write(script_contents)
        script_file.close()


        jdl_file = open(jdl_path,'w')

        jdl_contents =  '[\n'\
                        'Type="job";\n'\
                        'JobType="normal";\n'\
                        'VirtualOrganisation="' + vo + '";\n'\
                        'Environment={ "ENV_VAR=4cd5f61d5b9d68b1973e94e787b2bdf2" };\n'\
                        'Executable="' + script_name + '";\n'\
                        'StdOutput="job.out";\n'\
                        'StdError="job.err";\n'\
                        'InputSandbox={ "' + script_path + '" };\n'\
                        'OutputSandbox={ "job.out" , "job.err" };\n'\
                        'OutputSandboxBaseDestURI="gsiftp://localhost";\n'\
                        ']\n'


        jdl_file.write(jdl_contents)
        jdl_file.close()

        return (jdl_path,script_path)
##############################################################################################################################
##############################################################################################################################
def osb_basedesturi_jdl(vo, gridftp_server, gridftp_path, output_dir):
        '''
                |  Description: |    File transfer checking jdl file. Stage output files to a gridftp server,with the use of the        |
                |               |    OutputSandboxBaseDestURI jdl attribute.                                                            | \n
                |  Arguments:   |    vo              |  virtual organisation                                                            |
                |               |    gridftp_server  |  gridftp server for BaseDestURI                                                  |
                |               |    gridftp_path    |  gridftp path for BaseDestURI                                                    |
                |               |    output_dir      |  the directory to put the file in                                                | \n
                |  Returns:     |    Temporary file name.                                                                               |
        '''

        folder = output_dir
        identifier = 'osb_basedesturi'
        name = 'cream_testing-' + str(time.time()) + '-' + identifier + '.jdl'
        path = folder + '/' + name

        jdl_file = open(path,'w')

        jdl_contents =  '[\n'\
                        'Type="job";\n'\
                        'JobType="normal";\n'\
                        'VirtualOrganisation="' + vo + '";\n'\
                        'Executable="/bin/uname";\n'\
                        'Arguments="-a";\n'\
                        'StdOutput="job.out";\n'\
                        'StdError="job.err";\n'\
                        'OutputSandbox={ "job.out" , "job.err" };\n'\
                        'OutputSandboxBaseDestURI="gsiftp://' + gridftp_server + gridftp_path + '";\n'\
                        ']\n'


        jdl_file.write(jdl_contents)
        jdl_file.close()

        return path
##############################################################################################################################
##############################################################################################################################
def isb_client_to_ce_jdl(vo, output_dir):
        '''
                |  Description:  |  File transfer checking jdl file. Stage input files from client to CE node.  | \n
                |  Arguments:    |  vo            |  virtual organisation                                       |
                |                |  output_dir    |  the directory to put the file in                           | \n
                |  Returns:      |  Temporary jdl file name,temporary shell script file name.                   |
        '''

        folder = output_dir

        jdl_identifier = 'isb_client_to_ce'
        jdl_name = 'cream_testing-' + str(time.time()) + '-' + jdl_identifier + '.jdl'
        jdl_path = folder + '/' + jdl_name

        script_identifier = 'ls'
        script_name = 'cream_testing-' + str(time.time()) + '-' + script_identifier + '.sh'
        script_path = folder + '/' + script_name

        script_file = open(script_path,'w')

        script_contents =       '#!/bin/bash\n'\
                                '\n'\
                                'ls -l .\n'\
                                '\n'\
                                'exit $?\n'

        script_file.write(script_contents)
        script_file.close()


        jdl_file = open(jdl_path,'w')

        jdl_contents =  '[\n'\
                        'Type="job";\n'\
                        'JobType="normal";\n'\
                        'VirtualOrganisation="' + vo + '";\n'\
                        'Executable="' + script_name + '";\n'\
                        'StdOutput="job.out";\n'\
                        'StdError="job.err";\n'\
                        'InputSandbox={ "' + script_path + '" };\n'\
                        'OutputSandbox={ "job.out" , "job.err" };\n'\
                        'OutputSandboxBaseDestURI="gsiftp://localhost";\n'\
                        ']\n'


        jdl_file.write(jdl_contents)
        jdl_file.close()

        return (jdl_path,script_path)
##############################################################################################################################
##############################################################################################################################
def osb_desturi_jdl(vo, gridftp_server, gridftp_path, output_dir):
        '''
                |  Description: |    File transfer checking jdl file. Stage output files to a gridftp server,with the use of the        |
                |               |    OutputSandboxDestURI jdl attribute.                                                                | \n
                |  Arguments:   |    vo              |  virtual organisation                                                            |
                |               |    gridftp_server  |  gridftp server to set DestURI                                                   |
                |               |    gridftp_path    |  gridftp path to set DestURI                                                     |
                |               |    output_dir      |  the directory to put the file in                                                | \n
                |  Returns:     |    Temporary file name.                                                                               |
        '''

        folder = output_dir
        identifier = 'osb_desturi'
        name = 'cream_testing-' + str(time.time()) + '-' + identifier + '.jdl'
        path = folder + '/' + name

        jdl_file = open(path,'w')

        jdl_contents =  '[\n'\
                        'Type="job";\n'\
                        'JobType="normal";\n'\
                        'VirtualOrganisation="' + vo + '";\n'\
                        'Executable="/bin/uname";\n'\
                        'Arguments="-a";\n'\
                        'StdOutput="job2.out";\n'\
                        'StdError="job2.err";\n'\
                        'OutputSandbox={ "job2.out" , "job2.err" };\n'\
                        'OutputSandboxDestURI={\n'\
                        '                               "gsiftp://' + gridftp_server + gridftp_path + '/' + 'job2.out",\n'\
                        '                               "gsiftp://' + gridftp_server + gridftp_path + '/' + 'job2.err"\n'\
                        '                       };\n'\
                        ']\n'


        jdl_file.write(jdl_contents)
        jdl_file.close()

        return path
##############################################################################################################################
##############################################################################################################################
def prologue_jdl(vo, output_dir):
        '''
                |  Description: |   Attribute checking jdl file. Use the prologue argument and execute a prologue script.       | \n
                |  Arguments:   |   vo           |  virtual organisation                                                        |
                |               |   output_dir   |  the directory to put the file in                                            | \n
                |  Returns:     |   Temporary jdl file name,temporary shell script file name.,temporary prologue script.        |
        '''

        folder = output_dir

        jdl_identifier = 'prologue'
        jdl_name = 'cream_testing-' + str(time.time()) + '-' + jdl_identifier + '.jdl'
        jdl_path = folder + '/' + jdl_name

        script_identifier = 'ls'
        script_name = 'cream_testing-' + str(time.time()) + '-' + script_identifier + '.sh'
        script_path = folder + '/' + script_name

        prologue_identifier = 'prologue'
        prologue_name = 'cream_testing-' + str(time.time()) + '-' + prologue_identifier + '.sh'
        prologue_path = folder + '/' + prologue_name

        prologue_file = open(prologue_path,'w')

        prologue_contents =     '#!/bin/bash\n'\
                                '\n'\
                                'echo "Goodbye and thanks for all the fish!" >> prologue.txt\n'\
                                'echo "b71fa4b80bfa78785d57e42482a7fa04" >> prologue.txt\n'\
                                '\n'\
                                'exit $?\n'

        prologue_file.write(prologue_contents)
        prologue_file.close()

        script_file = open(script_path,'w')

        script_contents =       '#!/bin/bash\n'\
                                '\n'\
                                'ls -l .\n'\
                                '\n'\
                                'exit $?\n'

        script_file.write(script_contents)
        script_file.close()


        jdl_file = open(jdl_path,'w')

        jdl_contents =  '[\n'\
                        'Type="job";\n'\
                        'JobType="normal";\n'\
                        'VirtualOrganisation="' + vo + '";\n'\
                        'Prologue="' + prologue_name + '";\n'\
                        'Executable="' + script_name + '";\n'\
                        'StdOutput="job.out";\n'\
                        'StdError="job.err";\n'\
                        'InputSandbox={ "' + script_path + '" , "' + prologue_path + '" };\n'\
                        'OutputSandbox={ "job.out" , "job.err" , "prologue.txt" };\n'\
                        'OutputSandboxBaseDestURI="gsiftp://localhost";\n'\
                        ']\n'


        jdl_file.write(jdl_contents)
        jdl_file.close()

        return (jdl_path,script_path,prologue_path)
##############################################################################################################################
##############################################################################################################################
def epilogue_jdl(vo, output_dir):
        '''
                |  Description:  |  Attribute checking jdl file. Use the epilogue argument and execute an epilogue script.      | \n
                |  Arguments:    |  vo           |   virtual organisation                                                       |
                |                |  output_dir   |   the directory to put the file in                                           | \n
                |  Returns:      |  Temporary jdl file name,temporary shell script file name.,temporary epilogue script.        |
        '''

        folder = output_dir

        jdl_identifier = 'epilogue'
        jdl_name = 'cream_testing-' + str(time.time()) + '-' + jdl_identifier + '.jdl'
        jdl_path = folder + '/' + jdl_name

        script_identifier = 'ls'
        script_name = 'cream_testing-' + str(time.time()) + '-' + script_identifier + '.sh'
        script_path = folder + '/' + script_name

        epilogue_identifier = 'epilogue'
        epilogue_name = 'cream_testing-' + str(time.time()) + '-' + epilogue_identifier + '.sh'
        epilogue_path = folder + '/' + epilogue_name

        epilogue_file = open(epilogue_path,'w')

        epilogue_contents =     '#!/bin/bash\n'\
                                '\n'\
                                'echo "Am I supposed to do something here?Or just exist?" > epilogue.txt\n'\
                                'echo "8fb9391ad53014bdb49919e6a92606a5" >> epilogue.txt\n'\
                                '\n'\
                                'exit $?\n'

        epilogue_file.write(epilogue_contents)
        epilogue_file.close()

        script_file = open(script_path,'w')

        script_contents =       '#!/bin/bash\n'\
                                '\n'\
                                'ls -l .\n'\
                                '\n'\
                                'exit $?\n'

        script_file.write(script_contents)
        script_file.close()


        jdl_file = open(jdl_path,'w')

        jdl_contents =  '[\n'\
                        'Type="job";\n'\
                        'JobType="normal";\n'\
                        'VirtualOrganisation="' + vo + '";\n'\
                        'Prologue="' + epilogue_name + '";\n'\
                        'Executable="' + script_name + '";\n'\
                        'StdOutput="job.out";\n'\
                        'StdError="job.err";\n'\
                        'InputSandbox={ "' + script_path + '" , "' + epilogue_path + '" };\n'\
                        'OutputSandbox={ "job.out" , "job.err" , "epilogue.txt" };\n'\
                        'OutputSandboxBaseDestURI="gsiftp://localhost";\n'\
                        ']\n'


        jdl_file.write(jdl_contents)
        jdl_file.close()

        return (jdl_path,script_path,epilogue_path)
##############################################################################################################################
##############################################################################################################################
def isb_baseuri_jdl(vo, gridftp_server, gridftp_path, uploaded_file_name, output_dir):
        ''' 
                |  Description: |    File transfer checking jdl file. Store input files to a gridftp server,and use the jdl attribute   |
                |               |    InputSandboxBaseURI to fetch them.                                                                 | \n
                |  Arguments:   |    vo                   |   virtual organisation                                                      |
                |               |    gridftp_server       |   gridftp server to set ISBBaseURI                                          |
                |               |    gridftp_path         |   gridftp path to set ISBBaseURI                                            |
                |               |    uploaded_file_name   |   file name of the uploaded file                                            |
                |               |    output_dir           |   the directory to put the file in                                          | \n
                |  Returns:     |    Temporary file name.                                                                               |
        '''

        folder = output_dir
        identifier = 'isb_baseuri'
        name = 'cream_testing-' + str(time.time()) + '-' + identifier + '.jdl'
        path = folder + '/' + name

        if '/' in uploaded_file_name: #if the file name is a path, keep just the file name
                uploaded_file_name = uploaded_file_name.split('/')[-1]

        jdl_file = open(path,'w')

        jdl_contents =  '[\n'\
                        'Type="job";\n'\
                        'JobType="normal";\n'\
                        'VirtualOrganisation="' + vo + '";\n'\
                        'Executable="' + uploaded_file_name + '";\n'\
                        'InputSandbox = { "' + uploaded_file_name + '" };\n'\
                        'InputSandboxBaseURI = "gsiftp://' + gridftp_server + gridftp_path + '";\n'\
                        'StdOutput="job.out";\n'\
                        'StdError="job.err";\n'\
                        'OutputSandbox={ "job.out" , "job.err" };\n'\
                        'OutputSandboxBaseDestURI="gsiftp://localhost";\n'\
                        ']\n'

        jdl_file.write(jdl_contents)
        jdl_file.close()

        return path
##############################################################################################################################
##############################################################################################################################
def create_dummy_script(output_dir):
        '''
                |  Description:  |  Create a dummy bash script executing ls.             | \n
                |  Arguments:    |  output_dir    |  the directory to put the file in    | \n
                |  Returns:      |  Temporary file name                                  |
        '''


        folder = output_dir

        script_identifier = 'dummy'
        script_name = 'cream_testing-' + str(time.time()) + '-' + script_identifier + '.sh'
        script_path = folder + '/' + script_name

        script_file = open(script_path,'w')

        script_contents =       '#!/bin/bash\n'\
                                '\n'\
                                'ls -al .\n'\
                                '\n'\
                                'exit $?\n'

        script_file.write(script_contents)
        script_file.close()

        return script_path
##############################################################################################################################
##############################################################################################################################
def isb_gsiftp_to_ce_jdl(vo, gridftp_server, gridftp_path, uploaded_file_name, output_dir):
        '''
                |  Description:  |  File transfer checking jdl file. Store input files to a gridftp server,and use the jdl attribute    |
                |                |  InputSandbox to fetch them.                                                                         | \n
                |  Arguments:    |  vo                   |    virtual organisation                                                      |
                |                |  gridftp_server       |   gridftp server to set ISBBaseURI                                           |
                |                |  gridftp_path         |   gridftp path to set ISBBaseURI                                             |
                |                |  uploaded_file_name   |   file name of the uploaded file                                             |
                |                |  output_dir           |   the directory to put the file in                                           | \n
                |  Returns:      |  Temporary file name.                                                                                |
        '''

        folder = output_dir
        identifier = 'isb_gsiftp_to_ce'
        name = 'cream_testing-' + str(time.time()) + '-' + identifier + '.jdl'
        path = folder + '/' + name

        if '/' in uploaded_file_name: #if the file name is a path, keep just the file name
                uploaded_file_name = uploaded_file_name.split('/')[-1]

        jdl_file = open(path,'w')

        jdl_contents =  '[\n'\
                        'Type="job";\n'\
                        'JobType="normal";\n'\
                        'VirtualOrganisation="' + vo + '";\n'\
                        'Executable="' + uploaded_file_name + '";\n'\
                        'InputSandbox = { "gsiftp://' + gridftp_server + gridftp_path + '/' + uploaded_file_name + '" };\n'\
                        'StdOutput="job.out";\n'\
                        'StdError="job.err";\n'\
                        'OutputSandbox={ "job.out" , "job.err" };\n'\
                        'OutputSandboxBaseDestURI="gsiftp://localhost";\n'\
                        ']\n'


        jdl_file.write(jdl_contents)
        jdl_file.close()

        return path
##############################################################################################################################
##############################################################################################################################
def wait_for_status(jid, status):
        '''
                |  Description: |   Wait for the given job to reach the given status.   | \n
                |  Arguments:   |   jid         |    jod identifier                     |
                |               |   status      |    the status waiting for             | \n
                |  Returns:     |   Nothing                                             |
        '''

        while True:
                cur_status=get_current_status(jid)
                #print cur_status
                if cur_status == status :
                        return

##############################################################################################################################
##############################################################################################################################
def job_status_should_be(jid,status):
        '''
                |  Description: |   Check that the given job's status is the one given.     | \n
                |  Arguments:   |   jid        |     job identifier                         |
                |               |   status     |     the status comparing to                | \n
                |  Returns:     |   Nothing                                                 |
        '''

        cur_status=get_current_status(jid)
        if cur_status != status :
                raise _error("Expected status " + status + " for job " + jid + " was actually " + cur_status)
##############################################################################################################################
##############################################################################################################################
def qdel_job(jid, torque_host, torque_admin_user, torque_admin_pass):
        '''
                |  Description: |   Manually qdel a job.                                                                        | \n
                |  Arguments:   |   jid                |     job identifier                                                     |
                |               |   cream_host         |     the server hosting torque, either ip or name                       |
                |               |   cream_admin_user   |     a user exiting on the torque host, having admin priviledges        |
                |               |   cream_admin_pass   |     the aforementioned user's ssh password                             | \n
                |  Returns:     |   Nothing                                                                                     |
        '''

        num_jid = jid.split("CREAM")[1]

        print "Job ID is: " + jid

        ssh_con = paramiko.SSHClient()
        ssh_con.set_missing_host_key_policy(paramiko.AutoAddPolicy())  #don't ask for acceptance of foreign host key (auto accept)
        ssh_con.connect(torque_host, username=torque_admin_user, password=torque_admin_pass)

        time.sleep(10)  #a "safe" threshold to wait for the job to be registered in torque (i.e.: visible through qstat)

        stdin, stdout, stderr = ssh_con.exec_command("qstat")

        print "QSTAT stdout and stderr output follow"

        output = stdout.read()
        print output
        error = stderr.readlines()
        print error

        torque_jid = "not_set"
        for line in output.split('\n'):
                if num_jid in line:
                        torque_jid = line.split(' ')[0]
                        print "TORQUE jid is: " + torque_jid

        if torque_jid is "not_set":
                raise _error("Cream job with jid " + jid + " has not been found on the Torque server! (qstat didn't report it)")

        stdin, stdout, stderr = ssh_con.exec_command("qdel " + torque_jid)

        print "QDEL stdout and stderr output follow"
        
        output = stdout.read()
        print output
        error = stderr.readlines()
        print error

        print "Cream job with jid " + jid + " and torque jid " + torque_jid + " has been deleted!"

# Test the qdel_job() with the following method, after creating a proxy: (change cream endpoint and vo to a valid value)
#def test_qdel(torque_host, torque_admin_user, torque_admin_pass):
#        jdl = sleep_jdl("see","600")
#        jid = submit_job(jdl, "ctb04.gridctb.uoa.gr:8443/cream-pbs-see")
#        qdel_job(jid,torque_host,torque_admin_user,torque_admin_pass)
##############################################################################################################################
##############################################################################################################################
def execute_uberftp_command(uberftp_command, gridftp_server, gridftp_path):
        '''
                |  Description: |    Execute an uberftp command on a gridftp url                                                 | \n
                |  Arguments:   |    uberftp_command    |     one of cat,chgrp,chmod,dir,ls,mkdir,rename,rm,rmdir,size,stage     |
                |               |    gridftp_server     |     the gridftp server hostname                                        |
                |               |    gridftp_path       |     the path in the gridftp server                                     | \n
                |  Returns:     |    The output of the command                                                                   |
        '''

        valid_commands = "cat chgrp chmod dir ls mkdir rename rm rmdir size stage"

        if uberftp_command not in valid_commands:
                raise _error("Invalid uberftp command given: " + uberftp_command)

        com="uberftp -" + uberftp_command + " gsiftp://" + gridftp_server + gridftp_path
	args = shlex.split(com.encode('ascii'))

        p = subprocess.Popen( args , stderr=subprocess.STDOUT , stdout=subprocess.PIPE )
        fPtr=p.stdout

        output=fPtr.read()

        p.wait()

        if p.returncode != 0:
                raise _error('Uberftp command "' + com + '" failed with return code: ' + str(p.returncode) + ' \nCommand reported: ' +  output)

        print 'Uberftp command "' + com + '" output follows:'
        print output

        return output
##############################################################################################################################
##############################################################################################################################
def uberftp_upload(gridftp_server, gridftp_path, local_file_path):
        '''
                |  Description: |   Upload a file to a gridftp server with uberftp      | \n
                |  Arguments:   |   gridftp_server  |  the gridftp server hostname      |
                |               |  gridftp_path     |  the path in the gridftp server   |
                |               |  local_file_path  |  the full path of the local path  | \n
                |  Returns:     |   The output of the command                           |
        '''

        file_name = local_file_path.split('/')[-1]

        com='uberftp ' + gridftp_server + ' "cd ' + gridftp_path + ' ; put ' + local_file_path + ' ' + file_name + '"'
	args = shlex.split(com.encode('ascii'))

        p = subprocess.Popen( args , stderr=subprocess.STDOUT , stdout=subprocess.PIPE )
        fPtr=p.stdout

        output=fPtr.read()

        p.wait()

        if p.returncode != 0:
                raise _error('Uberftp command "' + com + '" failed with return code: ' + str(p.returncode) + ' \nCommand reported: ' +  output)

        print 'Uberftp command "' + com + '" output follows:'
        print output

        return output
##############################################################################################################################
##############################################################################################################################
def ce_service_info(ce_endpoint, verbosity):
        '''
                |  Description: |    Get the service info of a CREAM ce.                                |
                |  Arguments:   |    ce_endpoint  |  the CREAM endpoint                                 |
                |               |    verbosity    |  how much information will be shown, either 1 or 2  |
                |  Returns:     |    The output of the command                                          |
        '''

        verbosity = str(verbosity).encode('ascii')
        if verbosity != '1' and verbosity != '2':
                raise _error('Wrong verbosity given for glite-ce-service-info command.Must be either 1 or 2, you gave: ' + verbosity)

        com='glite-ce-service-info -L ' + verbosity + ' ' + ce_endpoint
	args = shlex.split(com.encode('ascii'))

        p = subprocess.Popen( args , stderr=subprocess.STDOUT , stdout=subprocess.PIPE )
        fPtr=p.stdout

        output=fPtr.read()

        p.wait()

        if p.returncode != 0:
                raise _error('Command "' + com + '" failed with return code: ' + str(p.returncode) + ' \nCommand reported: ' +  output)

        print 'Command "' + com + '" output follows:'
        print output

        return output
##############################################################################################################################
##############################################################################################################################
def validate_ce_service_info(output):
        '''
                |  Description:   |  Validates the output of a glite-ce-service-info command  | \n
                |  Arguments:     |  output  the output of the method ce_service_info()       | \n
                |  Returns:       |  Nothing (raises exception uppon non-validation)          |
        '''

        k=[]
        for line in output.split('\n'):
                if len(line) > 2: #do not search empty/too short lines
                        k.append(line)

        # Each line has the corresponding expected string beside it.
        # Each explainable regular expression is explained. Those too big were left empty.
        # Python regular expression syntax explanations:
        # \s     empty spaces of any kind (new lines,tabs etc included)
        # \d     any digit 0~9
        # \?     the char after '\' is escaped and searched for literally.e.g.: \: will search for ':'
        # [x-X]  the range between x and X is searched for.e.g.: [a-zA-Z] will match any alphabetic string
        # *      the star replicates the previous regular expression element zero or more times, as much as possible
        for i in range(len(k)):
                #print k[i]
                if i == 0:      # Interface Version  = [2.1]
                        # match 'Interface Version' - spaces - '=' - spaces - '[' - 0~9 digit - '.' - 0~9 digit - ']'
                        pattern = "Interface Version\s*=\s*\[\d\.\d\]"
                        match = re.search(pattern,k[i])
                        if match:
                                print 'Line ' + str(i) + ' did match.\nContents: "' + k[i] + '"'
                        else:
                                raise _error('Line ' + str(i) + ' did not match.\nContents:  ' + k[i] + '\nRegular expression: "' + pattern + '"')
                elif i == 1:    # Service Version    = [1.13]
                        # match 'Service Version' - spaces - '=' - spaces - '[' - 0~9 digit - '.' - 0~9 digit - 0~9 digit - ']'
                        pattern = "Service Version\s*=\s*\[\d\.\d\d\]"
                        match = re.search(pattern,k[i])
                        if match:
                                print 'Line ' + str(i) + ' did match.\nContents: "' + k[i] + '"'
                        else:
                                raise _error('Line ' + str(i) + ' did not match.\nContents:  ' + k[i] + '\nRegular expression: "' + pattern + '"')
                elif i == 2:    # Description        = [CREAM 2]
                        # match 'Decsription' - spaces - '=' - spaces - '[' - 'CREAM' - spaces - 0~9 digit - 0~9 digit - ']'
                        pattern = "Description\s*=\s*\[CREAM\s*\d\]"
                        match = re.search(pattern,k[i])
                        if match:
                                print 'Line ' + str(i) + ' did match.\nContents: "' + k[i] + '"'
                        else:
                                raise _error('Line ' + str(i) + ' did not match.\nContents:  ' + k[i] + '\nRegular expression: "' + pattern + '"')
                elif i == 3:    # Started at         = [Mon Nov  7 18:17:20 2011]
                        # match 'Started at' - spaces - '=' - spaces - '[' - day - spaces - month - spaces - 1 or 2 0~9 digits - two 0~9 digits - ':' - two 0~9 digits - ':' - two 0~9 digits - spaces - four 0~9 digits - ']'
                        pattern = "Started at\s*=\s*\[\Mon|Tue|Wen|Thu|Fri|Sat|Sun\s*Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec\s*\d|\d\d\s*\d\d\:\d\d\:\d\d\s*\d\d\d\d]"
                        match = re.search(pattern,k[i])
                        if match:
                                print 'Line ' + str(i) + ' did match.\nContents: "' + k[i] + '"'
                        else:
                                raise _error('Line ' + str(i) + ' did not match.\nContents:  ' + k[i] + '\nRegular expression: "' + pattern + '"')
                elif i == 4:    # Submission enabled = [YES]
                        # match 'Submission enabled' - spaces - '=' - spaces - '[' - 'YES' or 'NO' - ']'
                        pattern = "Submission enabled\s*=\s*\[YES|NO\]"
                        match = re.search(pattern,k[i])
                        if match:
                                print 'Line ' + str(i) + ' did match.\nContents: "' + k[i] + '"'
                        else:
                                raise _error('Line ' + str(i) + ' did not match.\nContents:  ' + k[i] + '\nRegular expression: "' + pattern + '"')
                elif i == 5:    # Status             = [RUNNING]
                        # match 'Status' - spaces - '=' - spaces - '[' - any alphabetical string - ']'
                        pattern = "Status\s*=\s*\[[a-zA-Z]*\]"
                        match = re.search(pattern,k[i])
                        if match:
                                print 'Line ' + str(i) + ' did match.\nContents: "' + k[i] + '"'
                        else:
                                raise _error('Line ' + str(i) + ' did not match.\nContents:  ' + k[i] + '\nRegular expression: "' + pattern + '"')
                elif i == 6:    # Service Property   = [cemon_url]->[NA]
                        # match 'Status' - spaces - '=' - spaces - '[' - cemon_url - ']' - '-' - '>' - '[' - any alphanumeric string containing ':','/' and '.' - ']'
                        pattern = "Service Property\s*=\s*\[cemon_url\]\-\>\[[a-zA-Z0-9:/.\-]*\]"
                        k[i]="Service Property   = [cemon_url]->[https://cream-35.pd.infn.it:8443/ce-monitor/services/CEMonitor]"
                        match = re.search(pattern,k[i])
                        if match:
                                print 'Line ' + str(i) + ' did match.\nContents: "' + k[i] + '"'
                        else:
                                raise _error('Line ' + str(i) + ' did not match.\nContents:  ' + k[i] + '\nRegular expression: "' + pattern + '"')
                elif i == 7:    # Service Property   = [SUBMISSION_THRESHOLD_MESSAGE]->[Threshold for Load Average(1 min): 40 => Detected value for Load Average(1 min):  0.00
                        #regular expression too big to explain
                        pattern = "Service Property\s*=\s*\[SUBMISSION_THRESHOLD_MESSAGE\]\-\>\[Threshold for Load Average\(\d* min\)\:\s\d*\s*\=\>\sDetected value for Load Average\(\d*\smin\)\:\s*\d*\.\d*"
                        match = re.search(pattern,k[i])
                        if match:
                                print 'Line ' + str(i) + ' did match.\nContents: "' + k[i] + '"'
                        else:
                                raise _error('Line ' + str(i) + ' did not match.\nContents:  ' + k[i] + '\nRegular expression: "' + pattern + '"')
                elif i == 8:    # Threshold for Load Average(5 min): 40 => Detected value for Load Average(5 min):  0.00
                        #regular expression too big to explain
                        pattern = "Threshold for Load Average\(\d*\s*min\)\:\s*\d*\s*\=\>\s*Detected value for Load Average\(\d*\s*min\)\:\s*\d*\.\d*"
                        match = re.search(pattern,k[i])
                        if match:
                                print 'Line ' + str(i) + ' did match.\nContents: "' + k[i] + '"'
                        else:
                                raise _error('Line ' + str(i) + ' did not match.\nContents:  ' + k[i] + '\nRegular expression: "' + pattern + '"')
                elif i == 9:    # Threshold for Load Average(15 min): 20 => Detected value for Load Average(15 min):  0.00
                        #regular expression too big to explain
                        pattern = "Threshold for Load Average\(\d*\s*min\)\:\s*\d*\s*\=\>\s*Detected value for Load Average\(\d*\s*min\)\:\s*\d*\.\d*"
                        match = re.search(pattern,k[i])
                        if match:
                                print 'Line ' + str(i) + ' did match.\nContents: "' + k[i] + '"'
                        else:
                                raise _error('Line ' + str(i) + ' did not match.\nContents:  ' + k[i] + '\nRegular expression: "' + pattern + '"')
                elif i == 10:    # Threshold for Memory Usage: 95 => Detected value for Memory Usage: 27.00%
                        #regular expression too big to explain
                        pattern = "Threshold for Memory Usage\:\s*\d*\s*\=\>\s*Detected value for Memory Usage\:\s*\d*\.\d*\%"
                        match = re.search(pattern,k[i])
                        if match:
                                print 'Line ' + str(i) + ' did match.\nContents: "' + k[i] + '"'
                        else:
                                raise _error('Line ' + str(i) + ' did not match.\nContents:  ' + k[i] + '\nRegular expression: "' + pattern + '"')
                elif i == 11:    # Threshold for Swap Usage: 95 => Detected value for Swap Usage: 0.00%
                        #regular expression too big to explain
                        pattern = "Threshold for Swap Usage\:\s*\d*\s*\=\>\s*Detected value for Swap Usage\:\s*\d*\.\d*\%"
                        match = re.search(pattern,k[i])
                        if match:
                                print 'Line ' + str(i) + ' did match.\nContents: "' + k[i] + '"'
                        else:
                                raise _error('Line ' + str(i) + ' did not match.\nContents:  ' + k[i] + '\nRegular expression: "' + pattern + '"')
                elif i == 12:    # Threshold for Free FD: 500 => Detected value for Free FD: 202418
                        #regular expression too big to explain
                        pattern = "Threshold for Free FD\:\s*\d*\s*\=\>\s*Detected value for Free FD\:\s*\d*"
                        match = re.search(pattern,k[i])
                        if match:
                                print 'Line ' + str(i) + ' did match.\nContents: "' + k[i] + '"'
                        else:
                                raise _error('Line ' + str(i) + ' did not match.\nContents:  ' + k[i] + '\nRegular expression: "' + pattern + '"')
                elif i == 13:    # Threshold for tomcat FD: 800 => Detected value for Tomcat FD: 96
                        #regular expression too big to explain
                        pattern = "Threshold for tomcat FD\:\s*\d*\s*\=\>\s*Detected value for Tomcat FD\:\s*\d*"
                        match = re.search(pattern,k[i])
                        if match:
                                print 'Line ' + str(i) + ' did match.\nContents: "' + k[i] + '"'
                        else:
                                raise _error('Line ' + str(i) + ' did not match.\nContents:  ' + k[i] + '\nRegular expression: "' + pattern + '"')
                elif i == 14:    # Threshold for FTP Connection: 30 => Detected value for FTP Connection: 1
                        #regular expression too big to explain
                        pattern = "Threshold for FTP Connection\:\s*\d*\s*\=\>\s*Detected value for FTP Connection\:\s*\d*"
                        match = re.search(pattern,k[i])
                        if match:
                                print 'Line ' + str(i) + ' did match.\nContents: "' + k[i] + '"'
                        else:
                                raise _error('Line ' + str(i) + ' did not match.\nContents:  ' + k[i] + '\nRegular expression: "' + pattern + '"')
                elif i == 15:    # Threshold for Number of active jobs: -1 => Detected value for Number of active jobs: 
                        #regular expression too big to explain
                        pattern = "Threshold for Number of active jobs\:\s*\-\d*\s*\=\>\s*Detected value for Number of active jobs\:\s*\d*"
                        match = re.search(pattern,k[i])
                        if match:
                                print 'Line ' + str(i) + ' did match.\nContents: "' + k[i] + '"'
                        else:
                                raise _error('Line ' + str(i) + ' did not match.\nContents:  ' + k[i] + '\nRegular expression: "' + pattern + '"')
                elif i == 16:    # Threshold for Number of pending commands: -1 => Detected value for Number of pending commands: 
                        #regular expression too big to explain
                        pattern = "Threshold for Number of pending commands\:\s*\-\d*\s*\=\>\s*Detected value for Number of pending commands\:\s*\d*"
                        match = re.search(pattern,k[i])
                        if match:
                                print 'Line ' + str(i) + ' did match.\nContents: "' + k[i] + '"'
                        else:
                                raise _error('Line ' + str(i) + ' did not match.\nContents:  ' + k[i] + '\nRegular expression: "' + pattern + '"')
                elif i == 17:    # Threshold for Disk Usage: 95% => Detected value for Partition / : 18%
                        #regular expression too big to explain
                        pattern = "Threshold for Disk Usage\:\s*\d*\%\s*\=\>\s*Detected value for Partition\s*[/a-zA-Z0-9]*\s*\:\s*\d*\%"
                        match = re.search(pattern,k[i])
                        if match:
                                print 'Line ' + str(i) + ' did match.\nContents: "' + k[i] + '"'
                        else:
                                raise _error('Line ' + str(i) + ' did not match.\nContents:  ' + k[i] + '\nRegular expression: "' + pattern + '"')
##############################################################################################################################
##############################################################################################################################
def proxy_info():
        '''
                |  Description:    Read user's proxy info.  | \n
                |  Arguments:      None.                    | \n
                |  Returns:        Command's output.        |
        '''

	if os.environ.has_key("X509_USER_PROXY") == False :
		raise _error("Proxy path env. var not set")

	if os.path.exists(os.environ["X509_USER_PROXY"]) == False :
		raise _error("Proxy file not present or inaccessible")

	com="/usr/bin/voms-proxy-info"
	args = shlex.split(com.encode('ascii'))
	p = subprocess.Popen( args , shell=False , stderr=subprocess.STDOUT , stdout=subprocess.PIPE )
	fPtr=p.stdout

        output=fPtr.read()

        p.wait()

        if p.returncode != 0:
                raise _error('Command "' + com + '" failed with return code: ' + str(p.returncode) + ' \nCommand reported: ' +  output)

        print 'Command "' + com + '" output follows:'
        print output
        print 'Command\'s output printed.'

        return output
##############################################################################################################################
##############################################################################################################################
def get_proxy_dn():
        '''
                |  Description:    Get user's proxy DN.  | \n
                |  Arguments:      none.                 | \n
                |  Returns:        The user's proxy DN.  |
        '''

        output = proxy_info()

        try:
                found=False
                for line in output.split('\n'):
                        pattern = "^subject\s*\:\s*"
                        match = re.search(pattern,line)
                        if match:
                                found=True
                                break
        finally:
                if found == False:
                        raise _error("DN couldn't be found in: " + output)
                else:
                        return line.split(":")[1].strip()
                        #print line.split(":")[1].strip()
##############################################################################################################################
##############################################################################################################################
def enable_cream_admin(dn, ce_endpoint, cream_root_pass):
        '''
                |  Description: |   Add the specified DN as a CREAM administrator (add it to /etc/grid-security/admin-list) | \n
                |  Arguments:   |   dn                 |    Distinguished Name to be added                                  |
                |               |   ce_endpoint        |    the cream endpoint                                              |
                |               |   cream_root_pass    |    cream host's root user's pass                                   | \n
                |  Returns:     |   Nothing (raises exception upon error)                                                   |
        '''

        cream_host = ce_endpoint.split(":")[0]
        file_path = "/etc/grid-security/admin-list"
        if "proxy" in dn:
                pattern = "/CN=proxy$"
                match = re.search(pattern,dn)
                if match: # DN ends with proxy."
                        dn = dn[:match.start()] + dn[match.end():]
                        print "final dn: " + dn
                else:
                        print "DN does not end with proxy"

        ssh_con = paramiko.SSHClient()
        ssh_con.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_con.connect(cream_host,22,'root',cream_root_pass)
        sftp = ssh_con.open_sftp()
        f = sftp.file(file_path,'a')

        f.write('"' + dn + '"\n')
        f.write('remove me\n')
        f.close()

        ssh_con.exec_command("touch /etc/grid-security/admin-list")
##############################################################################################################################
##############################################################################################################################
def disable_cream_admin(dn, ce_endpoint, cream_root_pass):
        '''
                |  Description:  |   Remove the specified DN as a CREAM administrator (add it to /etc/grid-security/admin-list)  | \n
                |  Arguments:    |   dn                |      Distinguished Name to be added                                     |
                |                |   ce_endpoint       |      the cream endpoint                                                 |
                |                |   cream_root_pass   |      cream host's root user's pass                                      | \n
                |  Returns:      |   Nothing (raises exception upon error)                                                       |
        '''

        cream_host = ce_endpoint.split(":")[0]
        file_path = "/etc/grid-security/admin-list"
        if "proxy" in dn:
                pattern = "/CN=proxy$"
                match = re.search(pattern,dn)
                if match: # DN ends with proxy."
                        dn = dn[:match.start()] + dn[match.end():]
                        print "final dn: " + dn
                else:
                        print "DN does not end with proxy"

        ssh_con = paramiko.SSHClient()
        ssh_con.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_con.connect(cream_host,22,'root',cream_root_pass)
        sftp = ssh_con.open_sftp()
        f = sftp.file(file_path,'r')

        # read file and keep only entries not containing the newly added dn
        entries_left=[]
        for line in f.readlines():
                if dn not in line:
                        entries_left.append(line)
        f.close()

        # delete the file (in order to write it again)
        sftp.remove(file_path)

        # write the old entries back in the file, after creating it
        f = sftp.file(file_path,'w')
        for item in entries_left:
                f.write(item)
                f.write('\n')
        f.write("remove me\n")
        f.close()

        ssh_con.exec_command("touch " + file_path)
##############################################################################################################################
##############################################################################################################################
def allowed_submission(ce_endpoint):
        '''
                |  Description:   |  Return the output of the glite-ce-allowed-submission command  | \n
                |  Arguments:     |  ce_endpoint      |      the cream endpoint                    | \n
                |  Returns:       |  the command's output.                                         |
        '''

        com='glite-ce-allowed-submission -d ' + ce_endpoint
	args = shlex.split(com.encode('ascii'))

        p = subprocess.Popen( args , stderr=subprocess.STDOUT , stdout=subprocess.PIPE )
        fPtr=p.stdout

        output=fPtr.read()

        p.wait()

        if p.returncode != 0:
                raise _error('Command "' + com + '" failed with return code: ' + str(p.returncode) + ' \nCommand reported: ' +  output)

        print 'Command "' + com + '" output follows:'
        print output

        return output.split('\n')[-2]
##############################################################################################################################
##############################################################################################################################
def enable_submission(ce_endpoint):
        '''
                |  Description:    Enable the submission to the designated CREAM endpoint. | \n
                |  Arguments:      ce_endpoint       |      the cream endpoint             | \n
                |  Returns:        nothing (raises exception in case of error)             |
        '''

        com='glite-ce-enable-submission -d ' + ce_endpoint
	args = shlex.split(com.encode('ascii'))

        p = subprocess.Popen( args , stderr=subprocess.STDOUT , stdout=subprocess.PIPE )
        fPtr=p.stdout

        output=fPtr.read()

        p.wait()

        if p.returncode != 0:
                raise _error('Command "' + com + '" failed with return code: ' + str(p.returncode) + ' \nCommand reported: ' +  output)

        print 'Command "' + com + '" output follows:'
        print output
##############################################################################################################################
##############################################################################################################################
def disable_submission(ce_endpoint):
        '''
                |  Description: |   Disable the submission to the designated CREAM endpoint. | \n
                |  Arguments:   |   ce_endpoint       |      the cream endpoint              | \n
                |  Returns:     |   nothing (raises exception in case of error)              |
        '''

        com='glite-ce-disable-submission -d ' + ce_endpoint
	args = shlex.split(com.encode('ascii'))

        p = subprocess.Popen( args , stderr=subprocess.STDOUT , stdout=subprocess.PIPE )
        fPtr=p.stdout

        output=fPtr.read()

        p.wait()

        if p.returncode != 0:
                raise _error('Command "' + com + '" failed with return code: ' + str(p.returncode) + ' \nCommand reported: ' +  output)

        print 'Command "' + com + '" output follows:'
        print output
##############################################################################################################################
##############################################################################################################################
def purge_job(jid, ce_endpoint):
        '''
                |  Description: |   Purge the job with the corresponding jid at the given CREAM endpoint  | \n
                |  Arguments:   |   jid                |     job id returned by job submit operation      |
                |               |   ce_endpoint        |     the CREAM endpoint                           | \n
                |  Returns:     |   nothing.                                                              |
        '''

        com="/usr/bin/glite-ce-job-purge -N -d -e " + ce_endpoint + " " + jid
        args = shlex.split(com.encode('ascii'))
        p = subprocess.Popen( args , shell=False , stderr=subprocess.STDOUT , stdout=subprocess.PIPE )
	fPtr=p.stdout

        retVal=p.wait()

        output=fPtr.read()

        if "error" in output.lower() or "fatal" in output.lower() or "fault" in output.lower() or retVal != 0 :
                raise _error('Command "' + com + '" failed with return code: ' + str(p.returncode) + ' \nCommand reported: ' +  output)
##############################################################################################################################
##############################################################################################################################
def get_job_sb(jid):
        '''
                |  Description:  |  Find the gridftp url of the ISB of the given job                 | \n
                |  Arguments:    |  jid             |       job id returned by job submit operation  | \n
                |  Returns:      |  (gridftp server, gridftp path)                                   |
        '''

        status_verbose = get_current_status_verbose(jid.encode('ascii'))

        print status_verbose

        try:
                gridftp_url = "not set"
                for line in status_verbose.split('\n'):
                        if "CREAM ISB URI" in line:
                                gridftp_url = line.split('=')[1].split('[')[1].split(']')[0][:-3]
        finally:
                if gridftp_url == "not set":
                        raise _error('Could not find the job\'s sandbox.')

        print gridftp_url

        server = gridftp_url.split('/var')[0].split('gsiftp://')[1]
        dir_path = '/var' + gridftp_url.split('/var')[1]

        return (server, dir_path)
##############################################################################################################################
##############################################################################################################################
def set_limiter_threshold(thresh_name, thresh_value, ce_endpoint, cream_root_pass):
        '''
                |  Description:  |  Set one threshold of the cream limiter perl script  |\n
                |  Arguments:    |  thresh_name      |  The threshold's name            |
                |                |  thresh_value     |  The threshold's value           |
                |                |  ce_endpoint      |  The cream host                  |
                |                |  cream_root_pass  |  Cream root password             |\n
                |  Returns:      |  Nothing                                             |
        '''

        cream_host = ce_endpoint.split(":")[0]

        valid_names = ['Load1', 'Load5', 'Load15', 'MemUsage', 'SwapUsage', 'FDNum', 'DiskUsage', 'FTPConn', 'FDTomcatNum', 'ActiveJobs', 'PendingCmds']

        if thresh_name not in valid_names:
                raise _error('Invalid threshold name. Must be one of "' + ','.join(valid_names) + '". You entered: ' + thresh_name)


        ssh_con = paramiko.SSHClient()
        ssh_con.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_con.connect(cream_host,22,'root',cream_root_pass)

        ssh_con.exec_command("rm -f /usr/bin/glite_cream_load_monitor.orig")
        ssh_con.exec_command("mv /usr/bin/glite_cream_load_monitor /usr/bin/glite_cream_load_monitor.orig")
        ssh_con.exec_command("cp /usr/bin/glite_cream_load_monitor.orig /usr/bin/glite_cream_load_monitor.tmp")

        sftp = ssh_con.open_sftp()
        src = sftp.file('/usr/bin/glite_cream_load_monitor.tmp','r')
        dest = sftp.file('/usr/bin/glite_cream_load_monitor','w')

        found = False
        for line in src.readlines():
                #print line
                if thresh_name in line and found == False:
                        print "FOUND!"
                        dest.write("$" + thresh_name + " = " + thresh_value + ";\n")
                        found = True
                else:
                        dest.write(line)

        src.close()
        dest.close()

        ssh_con.exec_command("rm -f /usr/bin/glite_cream_load_monitor.tmp")
        ssh_con.exec_command("chmod +x /usr/bin/glite_cream_load_monitor")
##############################################################################################################################
##############################################################################################################################
def reset_limiter_threshold(ce_endpoint, cream_root_pass):
        '''
                |  Description:  |  Reset the cream limiter perl script to the original unmodified one  |\n
                |  Arguments:    |  ce_endpoint       |  The cream host                                 |
                |                |  cream_root_pass   |  Cream root password                            |\n
                |  Returns:      |  Nothing                                                             |
        '''

        cream_host = ce_endpoint.split(":")[0]

        ssh_con = paramiko.SSHClient()
        ssh_con.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_con.connect(cream_host,22,'root',cream_root_pass)

        ssh_con.exec_command("mv -f /usr/bin/glite_cream_load_monitor.orig /usr/bin/glite_cream_load_monitor")
        ssh_con.exec_command("chmod +x /usr/bin/glite_cream_load_monitor")
##############################################################################################################################
##############################################################################################################################
def ban_user(dn, ce_endpoint, cream_root_pass):
        '''
                |  Description: |   Add the specified DN as a CREAM banned user (add it to /etc/lcas/ban_users.db)          | \n
                |  Arguments:   |   dn                 |    Distinguished Name to be added                                  |
                |               |   ce_endpoint        |    the cream endpoint                                              |
                |               |   cream_root_pass    |    cream host's root user's pass                                   | \n
                |  Returns:     |   Nothing (raises exception upon error)                                                   |
        '''

        cream_host = ce_endpoint.split(":")[0]
        file_path = "/etc/lcas/ban_users.db"
        if "proxy" in dn:
                pattern = "/CN=proxy$"
                match = re.search(pattern,dn)
                if match: # DN ends with proxy."
                        dn = dn[:match.start()] + dn[match.end():]
                        print "final dn: " + dn
                else:
                        print "DN does not end with proxy"

        ssh_con = paramiko.SSHClient()
        ssh_con.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_con.connect(cream_host,22,'root',cream_root_pass)
        sftp = ssh_con.open_sftp()
        f = sftp.file(file_path,'a')

        f.write('"' + dn + '"\n')
        f.close()

        #ssh_con.exec_command("touch " + file_path)
##############################################################################################################################
##############################################################################################################################
def unban_user(dn, ce_endpoint, cream_root_pass):
        '''
                |  Description:  |   Remove the specified DN as a CREAM banned user (remove it from /etc/lcas/ban_users.db)      | \n
                |  Arguments:    |   dn                |      Distinguished Name to be added                                     |
                |                |   ce_endpoint       |      the cream endpoint                                                 |
                |                |   cream_root_pass   |      cream host's root user's pass                                      | \n
                |  Returns:      |   Nothing (raises exception upon error)                                                       |
        '''

        cream_host = ce_endpoint.split(":")[0]
        file_path = "/etc/lcas/ban_users.db"
        if "proxy" in dn:
                pattern = "/CN=proxy$"
                match = re.search(pattern,dn)
                if match: # DN ends with proxy."
                        dn = dn[:match.start()] + dn[match.end():]
                        print "final dn: " + dn
                else:
                        print "DN does not end with proxy"

        ssh_con = paramiko.SSHClient()
        ssh_con.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_con.connect(cream_host,22,'root',cream_root_pass)
        sftp = ssh_con.open_sftp()
        f = sftp.file(file_path,'r')

        # read file and keep only entries not containing the newly added dn
        entries_left=[]
        for line in f.readlines():
                if dn not in line:
                        entries_left.append(line)
        f.close()

        # delete the file (in order to write it again)
        sftp.remove(file_path)

        # write the old entries back in the file, after creating it
        f = sftp.file(file_path,'w')
        for item in entries_left:
                f.write(item)
                f.write('\n')
        f.write("remove me\n")
        f.close()

        ssh_con.exec_command("touch " + file_path)
##############################################################################################################################
##############################################################################################################################
def change_sandbox_transfer_method(ce_endpoint, cream_root_pass):
        '''
                |  Description:  |   Change the SANDBOX_TRANSFER_METHOD between GSIFTP and LRMS (@ /etc/lcas/ban_users.db)       | \n
                |  Arguments:    |   ce_endpoint       |      the cream endpoint                                                 |
                |                |   cream_root_pass   |      cream host's root user's pass                                      | \n
                |  Returns:      |   Nothing (raises exception upon error)                                                       |
        '''

        cream_host = ce_endpoint.split(":")[0]
        file_path = "/etc/glite-ce-cream/cream-config.xml"

        ssh_con = paramiko.SSHClient()
        ssh_con.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_con.connect(cream_host,22,'root',cream_root_pass)

        ssh_con.exec_command("cp /etc/glite-ce-cream/cream-config.xml /etc/glite-ce-cream/cream-config.xml.orig")

        sftp = ssh_con.open_sftp()
        f = sftp.file(file_path,'r')

        # read file and modify only the entry for SANDBOX_TRANSFER_METHOD
        entries_left=[]
        for line in f.readlines():
                if "SANDBOX_TRANSFER_METHOD" in line:
                        if "GSIFTP" in line:
                                entries_left.append('    <parameter name="SANDBOX_TRANSFER_METHOD" value="LRMS" />\n')
                        elif "LRMS" in line:
                                entries_left.append('    <parameter name="SANDBOX_TRANSFER_METHOD" value="GSIFTP" />\n')
                        else:
                                raise _error("SANDBOX_TRANSFER_METHOD has an invalide value: " + line)
                else:
                        entries_left.append(line)
        f.close()

        # delete the file (in order to write it again)
        sftp.remove(file_path)

        # write the old entries back in the file, after creating it
        f = sftp.file(file_path,'w')
        for item in entries_left:
                f.write(item)
                #f.write('\n')
        f.close()

        ssh_con.exec_command("touch " + file_path)
##############################################################################################################################
##############################################################################################################################
def validate_glue(ce_endpoint, port, bind, glue_version):
        '''
                |  Description:  |   Run the glue validator for the designated CREAM endpoint                  | \n
                |  Arguments:    |   ce_endpoint       |      the cream endpoint                               |
                |                |   port              |      the ldap listening port                          |
                |                |   bind              |      the point where glue validator should bind       |
                |                |   glue_version      |      the glue version to be tested by glue validator  |\n
                |  Returns:      |   Nothing (raises exception upon error)                                     |
        '''

        cream_host = ce_endpoint.split(":")[0]

        #svn co http://svnweb.cern.ch/guest/gridinfo/glue-validator/trunk
        #export PYTHONPATH=${PYTHONPATH}:${PWD}/trunk/lib
        com='svn co http://svnweb.cern.ch/guest/gridinfo/glue-validator/trunk'
	args = shlex.split(com.encode('ascii'))
        p = subprocess.Popen( args , stderr=subprocess.STDOUT , stdout=subprocess.PIPE )
        fPtr=p.stdout
        output=fPtr.read()
        p.wait()
        if p.returncode != 0:
                raise _error('Command "' + com + '" failed with return code: ' + str(p.returncode) + ' \nCommand reported: ' +  output)
        else:
                print 'Command "' + com + '" output follows:'
                print output

        os.putenv('PYTHONPATH',str(os.getenv("PYTHONPATH")) + ":trunk/lib")

        com='trunk/bin/glue-validator -h ' + cream_host + ' -p ' + port + ' -b ' + bind + ' -t ' + glue_version
	args = shlex.split(com.encode('ascii'))
        p = subprocess.Popen( args , stderr=subprocess.STDOUT , stdout=subprocess.PIPE )
        fPtr=p.stdout
        output=fPtr.read()
        p.wait()
        if p.returncode != 0:
                raise _error('Command "' + com + '" failed with return code: ' + str(p.returncode) + ' \nCommand reported: ' +  output)
        else:
                print 'Command "' + com + '" output follows:'
                print output

        retVal = output

        com='rm -rf trunk/'
	args = shlex.split(com.encode('ascii'))
        p = subprocess.Popen( args , stderr=subprocess.STDOUT , stdout=subprocess.PIPE )
        fPtr=p.stdout
        output=fPtr.read()
        p.wait()
        if p.returncode != 0:
                raise _error('Command "' + com + '" failed with return code: ' + str(p.returncode) + ' \nCommand reported: ' +  output)
        else:
                print 'Command "' + com + '" output follows:'
                print output

        return retVal
##############################################################################################################################
##############################################################################################################################
