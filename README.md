# PS-Azure-SignIn-Log-To-GrayLog
Gets Azure AD Sign-in Logs from the last 15 minutes and Sends them to Graylog. 

Set up is a breeze:
Set up a new application and secret with directory access in Azure AD.
Add a new HTTP GELF input on your graylog instance.
Configure the script by adding your Client ID and secret and your new graylog input information. 
Add the script to a scheduled task set to run every 15 mins. 
Check your data is flowing into graylog, troubleshoot as necessary. 

Notes:

Geolocation data is formated properly and put into the ip_address_geolocation field! 
You can use the "World Map" button from search on that field, or add to a dashboard for greater effect.

0,0 Latitude / Longitude means Microsoft was not able to map the location to cordinates. These will appear to be just off the west coast of africa. Remember IP based location translation is not really accurate anyway.

The GUID field in the Graylog message / script is the login ID in Azure AD. Time stamp is imported as unix time.
I cut the millisecond digits off as graylog doesn't appear to handle them gracefully. Script DOES NOT round the second (Just substring)!






