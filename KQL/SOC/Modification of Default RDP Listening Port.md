//In the realm of cybersecurity, there's a strategic maneuver that sophisticated threat actors, 
commonly known as Advanced Persistent Threats (APTs), 
may employ to fly under the radar while exploiting Remote Desktop Protocol (RDP) connections. 
This tactic involves the subtle modification of the default RDP port (3389) to an unconventional port, 
thereby obscuring their activity from routine detection measures.....
.........................................................................................................



// Defining the investigative timeframe (set to 24 hours)
let Timeframe = 1d;

// Querying device registry events within the specified timeframe
DeviceRegistryEvents
| where Timestamp > ago(Timeframe)  // Narrowing down events based on a recent timeframe
| where RegistryKey == @"HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Terminal Server\WinStations\RDP-Tcp"  // Focusing on registry events pertaining to RDP configuration
| where RegistryValueName == @"PortNumber"  // Filtering events related to RDP port number
| where RegistryValueData != @"3389"  // Selecting events where the port number differs from the default (3389)
| where ActionType == @"RegistryValueSet"  // Identifying events where a registry value is being set
| project Timestamp, DeviceName, PreviousRegistryValueName, PreviousRegistryValueData, InitiatingProcessFileName  // Extracting key details for further analysis

////Feel free to use this version of the query and description! Let me know if there's anything else you need.





