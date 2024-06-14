# Threat hunting/detecting using KQL queries

```
  _  _____  _       
 | |/ / _ \| |     
 | ' | | | | |       
 | . | |_| | |___   
 |_|\_\__\_|_____|   
                                                                                                         
```                                                                                             



---
# KQL Training

### Microsoft Security Operations Analyst Associate (SC-200)
If Microsoft Sentinel and Microsoft 365 Defender are your daily to-go tools, you should consider following Microsoft's Certified Security Operations Analyst course (Exam code [SC-200](https://learn.microsoft.com/en-us/certifications/exams/sc-200/)). You will be acquainted with Microsoft's wide range of Security products and how you can use them to provide data, security signal and analyze alerts and incidents.

Be that as it may, you can jump into Microsoft's course that focus on KQL:
- [Utilize KQL for Azure Sentinel](https://learn.microsoft.com/en-us/training/paths/sc-200-utilize-kql-for-azure-sentinel/)
- [Configure Azure Sentinel environment](https://learn.microsoft.com/en-us/training/paths/sc-200-configure-azure-sentinel-environment/)

### Hands-On KQL for Threat Hunting and Detection Engineering

Mehmet Ergene (aka the [cyb3rmonk](https://twitter.com/cyb3rmonk) founded the blu raven academy where he offers the following KQL training courses, including hands-on experience in a hyper-realistic lab environment.
- ["Introduction to KQL for Security Analysis (FREE)"](https://academy.bluraven.io/intro-to-kql-for-security-analysis)
- ["Hands-On KQL for Threat Hunting and Detection Engineering"](https://academy.bluraven.io/hands-on-kusto-query-language-kql-for-security-analysts)
- [Hands-On Kusto Query Language (KQL) for Security Analysts](https://academy.bluraven.io/hands-on-kusto-query-language-kql-for-security-analysts) 

### Rod Trent's MustLearnKQL

[Rod Trent](https://github.com/rod-trent) created the [MustLearnKQL](https://github.com/rod-trent/MustLearnKQL) series which is a set of blog posts and Youtube videos comprising an effort to discuss and educate about the power and simplicity of the Kusto Query Language.

### CTF-a-like learning

- [KC7 Cyber](https://kc7cyber.com/) is a new way to learn cybersecurity that's hands-on, fun, and engaging.
- [Kusto Detective Agency](https://detective.kusto.io/) is a set of challenges that is designed to help you learn the KQL.

### Incident Response in the Microsoft Cloud

[Invictus](https://github.com/invictus-ir) created the [Incident Response in the Microsoft Cloud](https://academy.invictus-ir.com/advanced-incident-response-in-the-microsoft-cloud) training which covers how to do incident response in Microsoft Azure and Microsoft 365. This includes KQL basics, but also KQL querypacks and more advanced use cases and KQL queries for cloud attacks. 

---
# KQL Basics

### Choose appropriate table
Data is organized into a hierarchy of databases, tables and columns, similar to SQL. For example, the DeviceNetworkEvents table in the advanced hunting schema contains information about network connections and related events. 

### where operator
where filters on a specific predicate
```
DeviceNetworkEvents
| where LocalIP == "192.168.0.1"
```

### contains/has
- Contains: Looks for any substring match
- Has: Looks for a specific word (better performance)
```
DeviceNetworkEvents
| where DeviceName has "ComputerName"
```

### ago
Returns the time offset relative to the time the query executes
```
DeviceNetworkEvents
| where Timestamp > ago(1d)
```

### project
Selects the columns to include in the order specified
```
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where DeviceName has "ComputerName"
| project Timestamp, ActionType, RemoteIP, RemotePort, RemoteUrl
```

---
# Threat Hunting Basics
## Microsoft Threat Hunting
Threat hunting should be a continual process. We start at the top of our cycle with our Hypothesis. Our Hypothesis helps us plan out what we are going to hunt for, which requires us to understand where we're going to hunt and how we'll do it. This means we need to understand the data we have, the tools we have, the expertise we have, and how to work with them. The hunting cycle doesn't stop when we execute the hunt. There are still several phases we need to conduct throughout the life cycle, including responding to anomalies. Even if we don't find an active threat, there will be activities to perform. [More](https://learn.microsoft.com/en-us/training/paths/sc-200-perform-threat-hunting-azure-sentinel/).
<p align="center">
  <img src="https://images2.imgbox.com/d2/ac/Hz8cf39E_o.jpg">
</p>

## MITRE ATT&CK
The approach to hunting has two components: Characterization of malicious activity, and hunt Execution. These components should be ongoing activities, continuously updated based on new information about adversaries and terrain. [More](https://www.mitre.org/sites/default/files/2021-11/prs-19-3892-ttp-based-hunting.pdf).
<p align="center">
  <img src="https://images2.imgbox.com/e1/d9/lk1g8EPX_o.jpg">
</p>

---
# KQL Community

Contributing and sharing within the community is paramount as it fosters a collaborative environment where we all can exchange insights, challenges, and collectively advance our expertise. Following, you will find some of my bookmarked community resources.

### KQL Search

[KQL Search](https://www.kqlsearch.com/) is a project created by [Ugur Koc](https://github.com/ugurkocde) which aggregates GitHub repos from KQL community members that contribute queries for Microsoft Sentinel and Microsoft Defender XDR. This repo is also included along with other respectful members effort to build better defenses with the Microsoft Security stack.

