//This cheat sheet serves as a primer for the Kusto Query Language (KQL), focusing on the essentials. It primarily utilizes the SecurityEvent table, which can be accessed via https://aka.ms/lademo. Throughout the queries, the SecurityEvent table is represented by the abbreviation T. Links to official KQL documentation are provided for various functions and operators. Please note that while the example queries aim to elucidate KQL usage, they may cease to yield results if there are alterations in the data on the Log Analytics demo portal.


1- To handle a backslash within a string literal, it must be escaped by another backslash:
"a string literal with a \\ requires escaping."
Alternatively, you can utilize a verbatim string literal by prefixing with the @ sign:
@"a string literal with a \ that doesn't need escaping."
Add comments to your query with a double forward slash:
// This is a comment


2- The where operator and the pipe (|) delimiter are fundamental elements in crafting KQL queries.

The where operator serves to sift through rows within a table. For instance, in the following example, we filter events from a specific source, the SecurityEvent table, where the Computer column contains "example.com", and subsequently tally the number of occurrences:
"SecurityEvent
| where Computer has "example.com"
| count"
The pipe symbol (|) delineates data transformation operators. For instance, after filtering rows based on a condition like where Computer has "example.com", the resultant dataset can be further processed or directed elsewhere using the pipe symbol.


3-To exclusively capture events from the past 24 hours, leverage the ago() function:

"table name
| where TimeGenerated > ago(24h)
For optimal performance, prioritize time filters at the beginning of your query.
The ago() function supports various timespan specifications, such as:
1d for 1 day
10m for 10 minutes
30s for 30 seconds"
To include events within a specific timeframe:
"Table name:
| where TimeGenerated between(datetime(2022-08-01 00:00:00) .. datetime(2022-08-01 06:00:00))"




4- To customize the resulting table of your query, you can use the project operator to select specific columns and optionally rename them:

Specify the columns to include:

Table name
| project TimeGenerated, EventID, Account, Computer, LogonType
Rename columns, for instance, renaming the column "Account" to "UserName":


Table name
| project TimeGenerated, EventID, UserName = Account, Computer, LogonType
To remove specific columns, utilize the project-away operator:


Table name
| project-away EventSourceName, Task, Level
You can add calculated columns to the result using the extend operator. For example, to calculate the age of each event:

Table name
| extend EventAge = now() - TimeGenerated
Lastly, to count the number of records, use the count operator:

Table name
| count



Perform conditional matching using logical operators. For instance:
• Filter based on conditions:
T | where EventID equals 4624 and LogonType equals 3
T | where EventID equals 4624 or EventID equals 4625
T | where (EventID equals 4624 and LogonType equals 3) or EventID equals 4625

Aggregate results using the summarize operator:
• Aggregate on multiple columns:
T | summarize by Computer, Account
• Aggregate on multiple columns and count the groups:
T | summarize count() by Computer, Account

Sort the rows of the result using the sort operator:
T | where EventID equals 4624 | summarize count() by AuthenticationPackageName | sort by count_ asc
You can also sort in descending order using 'desc'.

Concatenate values into a string:
T | project example = strcat(EventID, " - ", Channel)

Search for a specific value:
T | where EventID equals 4688
Use '!=' for 'not equal to'.

Search for values less than or greater than:
T | where EventID equals 4688 | summarize count() by Process | where count_ less than 5
Use '>' for 'greater', '<=' for 'less or equal', and '>=' for 'greater or equal'.

Match on multiple numeric values:
T | where EventID in (4624, 4625)

Extract values from strings or JSON data:
SecurityAlert | extend _ProcessName = extract('"process name": "(.*)"', 1, ExtendedProperties)
For JSON data, you can also use extractjson():
SecurityAlert | extend _ProcessName = extractjson("$.process name", ExtendedProperties)
For multiple elements extraction, use parse_json(). Use the dot notation if the data is stored as a dictionary or a list of dictionaries in an array. You can determine the type using the gettype() function. For example:
SigninLogs | project Status.errorCode


Searching Across All Tables and Columns for a Keyword:

To perform a comprehensive search across all tables and columns, use the syntax:


search "*KEYWORD*"
However, bear in mind that this operation is resource-intensive.

Searching for a Specific Value:

To find a specific value, such as the process name "C:\Windows\System32\svchost.exe", use:


T | where ProcessName == @"C:\Windows\System32\svchost.exe"
For a not equal to match, prefix the condition with an exclamation mark:


T | where ProcessName != @"C:\Windows\System32\svchost.exe"
Case Sensitivity and Insensitivity:

For case sensitivity, use ==, while =~ denotes case insensitivity. For example:


T | where ProcessName == "example"     // Case sensitive
T | where ProcessName =~ "example"    // Case insensitive
Matching Values Containing a Specific String:

To find values containing a specific string, use contains. Prefer has over contains for performance. For example:


T | where CommandLine contains "guest"
To ensure case sensitivity, use contains_cs or has_cs.

Matching Values Starting With or Ending With a String:

For values starting or ending with a string, use startswith or endswith. For example:


T | where Computer startswith "DC"
To enforce case sensitivity, append _cs to the function name.

Matching Multiple String Values:

To match multiple string values, use in. For example:


T | where Computer in ("DC01.na.contosohotels.com", "JBOX00")
To negate the match, use !in. For case insensitivity, use in~ or !in~.

Using Regular Expressions:

For regex matching, employ matches regex. For instance:


T | where Computer matches regex @"\.contoso.+"
Troubleshoot regex patterns using regex101.com, selecting the "Golang" flavor.

Not Equal to Match with Regular Expressions:

To perform a not equal to match using regular expressions, use the not() function. For example:

T | where not(Computer matches regex @"\.contoso.+")
