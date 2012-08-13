#!/bin/bash

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

#              +-------------+
#              |             |
#              |  have key?  |
#              +------+------+
#                     |
#                     |
#      +-------+      |
#      |       |  No  |  Yes +------------+             +-----------+    +------------+
#      | create|<-----+----->| create new?|   No        | copy      |    |            |
#      | key   |             |            |+----------->| to        |+-->|   Done     |
#      +-+-----+             ++-----------+             | hosts     |    |            |
#        |  ^       Yes       |                         +-----------+    +------------+
#        |  +-----------------+                          ^
#        |                        (new key creted)       |
#        +-----------------------------------------------+
#
# credits for the above exceptional ascii diagram go to http://www.asciiflow.com/



get_host_name()
{
        while true; do
                hn=$(whiptail --title "Cream Testing SSH Key Setup" --inputbox "Please enter the $1 host name" 10 50 3>&1 1>&2 2>&3)
                exitstatus=$?
                if [ $exitstatus == 0 ]; then
                        if [ ${#hn} -gt 0 ]; then
                                host_name=${hn//;/} #simplest sanitizing, just in case
                                break
                        else
                                echo ''
                                return
                        fi
                else
                        echo ''
                        return
                fi
        done

        echo $host_name
}

location=$HOME"/.ssh/id_rsa"

whiptail --title "Welcome to the Cream Testing SSH Key Generator!" --msgbox "This is an automated script to guide you through the process of creating and/or using the appropriate keys needed by the automated cream test suite. Press <enter> to continue" 10 50

whiptail --title "Welcome to the Cream Testing SSH Key Generator!" --msgbox "The key pair needs to reside under the default location ~/.ssh/id_rsa and ~/.ssh/id_rsa.pub. Any existing key pair will be backed up. Press <enter> to continue" 10 50

whiptail --title "Cream Testing SSH Key Setup" --yesno "Do you allready have a passwordless id_rsa/id_rsa.pub key pair?" 10 50

exitstatus=$?
if [ $exitstatus == 0 ]; then
        has_key="yes"
else
        has_key="no"
fi

if [ $has_key == "no" ]; then
        create="yes"
elif [ $has_key == "yes" ]; then

        if [ ! -f ~/.ssh/id_rsa ] && [ ! -f ~/.ssh/id_rsa.pub ]; then
                whiptail --title "Cream Testing SSH Key Setup" --msgbox "No key pair found. Will create new one. Press <enter> to continue" 10 50
                has_key="no"
                create="yes"
        else
                whiptail --title "Cream Testing SSH Key Setup" --yesno "Do you want to create a new key pair?" 10 50
                exitstatus=$?
                if [ $exitstatus == 0 ]; then
                        create="yes"
                else
                        create="no"
                fi
        fi
fi

if [ $create == "yes" ]; then
        if [ $has_key == "yes" ]; then
                #make backup
                now=`date +%F_%s`
                mv ~/.ssh/id_rsa ~/.ssh/id_rsa.backup_at_$now
                mv ~/.ssh/id_rsa.pub ~/.ssh/id_rsa.pub.backup_at_$now
        fi

        ssh-keygen -q -t rsa -N '' -f "$location"
fi

while true; do
        choice=$(whiptail --title "Cream Testing SSH Key Setup" --menu "Chose an option" 15 50 5 \
                "1." "Add key to CREAM Host" \
                "2." "Add key to LRMS Host" \
                "3." "Add key to ARGUS Host" \
                "Exit" "Select this once you are done"  3>&1 1>&2 2>&3)

        if [ $choice == "Exit" ]; then
                exit 1
        elif [ $choice == "1." ]; then
                host_name=$(get_host_name "CREAM")
                if [ ${#host_name} -gt 0 ]; then
                        ssh-copy-id -i $location root@${host_name}
                fi
        elif [ $choice == "2." ]; then
                host_name=$(get_host_name "LRMS")
                if [ ${#host_name} -gt 0 ]; then
                        ssh-copy-id -i $location root@${host_name}
                fi
        elif [ $choice == "3." ]; then
                host_name=$(get_host_name "ARGUS")
                if [ ${#host_name} -gt 0 ]; then
                        ssh-copy-id -i $location root@${host_name}
                fi
        fi

done


exit 0
