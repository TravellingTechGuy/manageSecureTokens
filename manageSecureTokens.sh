#!/bin/bash

# Travelling Tech Guy - 7/12/18
# Script created as proof of concept for blogpost https://travellingtechguy.eu/script-secure-tokens-mojave

# The idea is to run this prior to enabling FileVault remotely.
# This to ensure we have the correct Secure Tokens in place in case you want to manipulate Secure Tokens with an 'IT Admin' accouont later.
# Mainly to avoid ending up with a FileVault Enabled Mac, with only a tokenised non-admin enduser.

# Script below uses $4 and $5 to pass the "IT Admin" credentials, but I would recommend to have a look at the GitHub link below to add more security.
# Encrypt Admin credentials passed via script in Jamf Pro: https://github.com/jamfit/Encrypted-Script-Parameters/blob/master/EncryptedStrings_Bash.sh

# AS ALWAYS: script provided AS IS. Mainly a proof of concept for the above blogpost. TEST and EVALUATE before using it in production.


# Check if a User is logged in
if pgrep -x "Finder" \
&& pgrep -x "Dock" \
&& [ "$CURRENTUSER" != "_mbsetupuser" ]; then

# additional Admin credentials
addAdminUser=$4
#add encryption
addAdminUserPassword=$5

# Check if our admin has a Secure Token

  		if [[ $("/usr/sbin/sysadminctl" -secureTokenStatus "$addAdminUser" 2>&1) =~ "ENABLED" ]]; then
  		adminToken="true"
  		else
    	adminToken="false"
    	fi
  		echo "Admin Token: $adminToken"

# Check if FileVault is Enabled
# I'm not using this variable in the rest of the script. Only added it in case you want to customise the script and enable FileVault at the end if 'fvStatus' is false
		
		if [[ $("/usr/bin/fdesetup" status 2>&1) =~ "FileVault is On." ]]; then
  		fvStatus="true"
  		else
  		fvStatus="false"
  		fi
  		echo "FV Status: $fvStatus"

# Check Secure Tokens Status - Do we have any Token Holder?

		if [[ $("/usr/sbin/diskutil" apfs listcryptousers / 2>&1) =~ "No cryptographic users" ]]; then
	  	tokenStatus="false"
	  	else
	  	tokenStatus="true"	
		fi
		echo "Token Status $tokenStatus"


				# Get the current logged in user
				userName=$(/usr/bin/python -c 'from SystemConfiguration import SCDynamicStoreCopyConsoleUser; import sys; username = (SCDynamicStoreCopyConsoleUser(None, None, None) or [None])[0]; username = [username,""][username in [u"loginwindow", None, u""]]; sys.stdout.write(username + "\n");')

				# Check if end user is admin

					if [[ $("/usr/sbin/dseditgroup" -o checkmember -m $userName admin / 2>&1) =~ "yes" ]]; then
  					userType="Admin"
  					else
  					userType="Not admin"
					fi
					echo "User type: $userType"

				# Check Token status for end user

				  	if [[ $("/usr/sbin/sysadminctl" -secureTokenStatus "$userName" 2>&1) =~ "ENABLED" ]]; then
  					userToken="true"
  					else
			    	userToken="false"
			    	fi
			  		echo "User Token: $userToken"

				# If both end user and additional admin have a secure token

				if [[ $userToken = "true" && $adminToken = "true" ]]; then
				echo "All is good!"
				exit 0
				fi

				# Prompt for password
				echo "Prompting ${userName} for their login password."
				userPass="$(/usr/bin/osascript -e 'Tell application "System Events" to display dialog "Please enter your current password" default answer "" with title "FileVault Configuration" with text buttons {"Ok"} default button 1 with hidden answer' -e 'text returned of result')"

								# Check if the password is ok
								passDSCLCheck=`dscl /Local/Default authonly $userName $userPass; echo $?`

								# If password is not valid, loop and ask again
								while [[ "$passDSCLCheck" != "0" ]]; do
								echo "asking again"
								userPassAgain="$(/usr/bin/osascript -e 'Tell application "System Events" to display dialog "Wrong Password!" default answer "" with title "Login Password" with text buttons {"Ok"} default button 1 with hidden answer' -e 'text returned of result')"
								userPass=$userPassAgain
								passDSCLCheck=`dscl /Local/Default authonly $userName $userPassAgain; echo $?`
								done 

								if [ "$passDSCLCheck" -eq 0 ]; then
								    echo "Password OK for $userName"
								fi

				# If additional admin has a token but end user does not

				if [[ $adminToken = "true" && $userToken = "false" ]]; then
				sysadminctl -adminUser $addAdminUser -adminPassword $addAdminUserPassword -secureTokenOn $userName -password $userPass

				echo "Token granted to end user!"

				diskutil apfs listcryptousers /
				fi

				# If no Token Holder exists, just grant both admin and end user a token
				if [[ $tokenStatus = "false" && $userToken="false" ]]; then
				sysadminctl -adminUser $addAdminUser -adminPassword $addAdminUserPassword -secureTokenOn $userName -password $userPass

				echo "Token granted to both additional admin and end user!"

				diskutil apfs listcryptousers /
				fi

				# If end user is an admin Token holder while our additional admin does not have one

				if [[ $userType = "Admin" && $userToken = "true" && $adminToken = "false" ]]; then
				sysadminctl -adminUser $userName -adminPassword $userPass -secureTokenOn $addAdminUser -password $addAdminUserPassword

				echo "End user admin token holder granted token to additional admin!"

				diskutil apfs listcryptousers /
				fi

				# If end user is a non-admin token holder and our additional admin does not have a Token yet

				if [[ $userType = "Not admin" && $userToken = "true" && $adminToken = "false" ]]; then
				echo "Houston we have a problem!"
				#Here you could update an extension attribute (API CALL) to group problematic Macs in a smart group.
				#The only workaround to fix this is to promote the end user to admin, leverage it to manipulate the tokens and demote it again.
				#I tried it, it works and it does not harm the tokens.
				dscl . -append /groups/admin GroupMembership $userName
				echo "End user promoted to admin!"

				sysadminctl -adminUser $userName -adminPassword $userPass -secureTokenOn $addAdminUser -password $addAdminUserPassword
				echo "End user admin token holder granted token to additional admin!"

				diskutil apfs listcryptousers /

				dscl . -delete /groups/admin GroupMembership $userName
				echo "End user demoted back to standard!"	
				#exit 1
				fi

# Here you could call a custom trigger to run a jamf Policy enabling FileVault
#	or update smartgroup via 'jamf recon' to push a Configuration Profile to enable Filevault via an extension attribute (API CALL.

# In case you are running this script on Macs where FileVault was already enabled, your admin account will still get a Secure Token,
#	... unless your non-admin end user was the only token holder.
# However, creating Secure Tokens post FileVault enablement does not make the account show up ad preBoot automatically.
# 	... you will need to run the following command to do so.
# diskutil apfs updatepreBoot /

# This compared to the fact that enabling FileVault does add all existing Secure Token Holders automatically to the preBoot Filevault enabled users

else
	echo "No user logged in"
	exit 1
fi 
