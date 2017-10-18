# FireEye Integration
Cb Response provides integration with an on-premise FireEye, Inc. device for correlating FireEye alerts with data that is collected by Cb Response. More information about FireEye can be found at www.fireeye.com.
To support this integration, Cb Response provides an out-of-band connector that receives alerts from the FireEye device and communicates this information to the Cb Response server through a listener on port 3000.
Alerts are received in the form of IPv4 and DNS addresses, and MD5 hashes. The listener parses the event data from FireEye into Cb Response JSON feed format for presentation to a feed that can be made available through the Cb Response console interface.
Sections

# FireEye Installation
Install the Cb Response out-of-band connector to receive FireEye alerts on the Cb Response server.
## To install the connector:
1. Ensure that the following prerequisites are met:
 	* Cb Response server installation version 5.0 or later is installed with Internet connectivity.
 	* FireEye is installed on a device.
2. Configure the Cb Response open source connectors YUM repository as described in “Setting up the Open Source Connector Repository” on page 15.
3. Verify the Yum configuration and install the FireEye connector:

		yum info python-cb-fireeye-connector 
		yum install python-cb-fireeye-connector
	
4. In the Cb Response console interface, retrieve the API key for the user you intend to use for the FireEye integration:
	1. On the Cb Response console, login with the account you selected. (This user must have administrative rights on the server.)
	2. In the top-right corner of the Cb Response console, select Username > My Profile.
	3. On the My Profile page, choose API Token in the left menu. Leave this page open so the information is available to you.

5. Edit the FireEye connector configuration file. You can find the FireEye connector configuration file on the Cb Response server at this location:

	`/etc/cb/integrations/carbonblack_fireeye_bridge/ carbonblack_fireeye_bridge.conf`
	1. Update the carbonblack_server_url option to set the URL of the Cb Response server.
	2. Copy the API Token string displayed in the API Token field in the Cb Response console (see step 4), and update the carbonblack_server_token value with the token you copied.
	3. The remainder of the options are documented in the configuration file and can be customized as needed to match specific requirements.
	4. Save the configuration file.
6. Start the FireEye connector on the Cb Response server:

	`# /etc/init.d/cb-fireeye-bridge start`
7. Examine the FireEye connector log to verify that the service is running normally:

	`# tail -f /var/log/cb/integrations/carbonblack_fireeye_bridge/ carbonblack_fireeye_bridge.log`
8. Edit iptables on the Cb Response server to open TCP 3000 to receive FireEye alerts, and then restart it.
	1. Enter the following:
	
		`# vi /etc/sysconfig/iptables`
	2. Add the following line to iptables and then save the file:

		`-A INPUT -m state --state NEW -m tcp -p tcp --dport 3000 -j ACCEPT`
	3. Restart iptables to apply your change:

		`# service iptables restart`

9. Test that the FireEye connector is operational and ready to receive alerts by going to http://<cbserver-ip>:3000 in a browser with network connectivity to your Cb Response server, replacing “<cbserver-ip>” with the IP address or hostname of your Cb Response server.

# Start and Stop the FireEye Connector
## To start the FireEye connector:
`# service /etc/init.d/cb-fireeye-connector start`
## To stop the FireEye connector:
`# service /etc/init.d/cb-fireeye-connector stop`


# FireEye Device Configuration
The FireEye device must be configured to send notifications to the Cb Response server.
To configure a FireEye device to provide a Cb Response feed:
1. Open the FireEye web interface and go to Settings Notifications.
2. Click on the red HTTP column header to display the HTTP Server Listing panel.
3. In the Add HTTP Server Name box, enter CarbonBlack .
4. Click the Add HTTP Server button.
5. Check the Enabled box next to the new server and in the Server URL field, enter the URL for the Cb Response server listener:

	`http://<serveraddress>:3000/fireeye/alert`


6. For Notification, choose All Events on the menu.
7. For Delivery, choose Per Event.
8. For Default Provider, choose Generic.
9. For Message Format, choose JSON Normal.
10. Click Update.
11. Click Test-Fire.
12. Enable the HTTP protocol.
13. Browse to http://<serveraddress>:3000/ to see the Test event.
	1. Scroll down to Feed Contents.
	2. Click HTML.
	3. If you have issues with the URL, check the contents of the "JSON" page here for the pre-programmed URL or use tail -f to look for a connection event in the log file:
	
		`/var/log/cb/integrations/carbonblack_fireeye_bridge/ carbonblack_fireeye_bridge.log`
