# Authenticated enumeration
* [General](#General)
* [Enumeration through Google Cloud portal](#Enumeration-through-Google-Cloud-portal)
* [Enumeration using gcloud CLI](#Enumeration-using-gcloud-CLI)
  * [Authentication](#Authentication)
  * [Resource Hierarchy](#Resource-Hierarchy)
  * [Projects](#Projects)
  * [IAM](#IAM)
    * [Policies](#Policies)
    * [Roles](#Roles) 
    * [ORG policies](#ORG-policies)
    * [Bruterforce Permissions](#Bruterforce-Permissions)
  * [Service Accounts](#Service-accounts)
  * [Virtual machines](#Virtual-machines)
  * [Networking](#Networking)
  * [Function Apps](#Function-Apps)
  * [Storage Buckets](#Storage-Buckets)
  * [Webapps and SQL](#Webapps-and-SQL)
  * [Containers](#Containers)
  * [Serverless](#Serverless)
* [Enumeration using Google Cloud API](#Enumeration-using-Google-Cloud-API)
* [Automated Tools](#Automated-Tools)
  * [GCP_Scanner](#GCP_Scanner) 

## General
## Enumeration through Google Cloud portal
- Google Cloud login at https://console.cloud.google.com/
- Google Workspace admin login at https://admin.google.com/
- Google Workspace user access https://myaccount.google.com/
  - Mail https://mail.google.com/
  - Google Drive https://drive.google.com/
  - Contacts https://contacts.google.com/

## Enumeration using gcloud CLI
- Documentation: https://cloud.google.com/sdk/gcloud/reference
- Most GCP instances have Google Cloud SDK installed
- `gcloud` CLI tool for managing auth, config, and interacting with GCP services
- `gsutil` CLI tool for accessing GCP storage buckets
- Possible to use access token with `--access-token-file=`

#### Gcloud services and commands
```
gcloud
```

### Authentication
#### User account 
- Login through the GUI with Username & Pass
```
gcloud auth login
```

#### Service account login
- Json key file
```
gcloud auth activate-service-account --key-file <JSON FILE>
```

#### User Account - Username & Pass - External application login
- Also known as Application Default Credential
- Login through the GUI with Username & Pass and creates `application_default_credentials.json`
```
gcloud auth application-default login
```

#### Service Account - External application
- Also known as Application Default Credential
- Used for Terraform for example
```
$env:GOOGLE_APPLICATION_CREDENTIALS="<PATH TO OF .json OF SERVICE ACCOUNT>"
dir env:
```

#### Access token
- Use the `--access-token-file=` or use the following tool:
- https://github.com/RedTeamOperations/GCPTokenReuse
```
python3 /opt/gc/GCPTokenReuse/Gcp-Token-Updater.py -I --access-token "<ACCESS TOKEN>" --account-name <ACCOUNT NAME>
```

#### Get the current user
```
gcloud auth list
```

#### Change between user
```
gcloud config set account <ACCOUNT>
```

#### Get config of all sessions/users
- Such as project set etc.
- Usefull if using multiple users
```
gcloud config list
```

### Resource Hierarchy
- Organization --> Folders --> Projects --> Resources

#### List google cloud organizations the user has access too
```
gcloud organizations list
```

#### List GCP folders
```
gcloud resource-manager folders list --organization <ORG ID>
```

#### List resources
- Required `cloudasset.googleapis.com` to be enabled for project
```
gcloud beta asset search-all-resources
```

### Projects
- All Google Cloud resources are in projects. When quering for resources it is limited to the projects. You gotta change projects to enumerate everything!

#### Get projects
```
gcloud projects list
```

#### Get hierachy of project
```
gcloud projects get-ancestors <PROJECT ID>
```

#### Set a project
```
gcloud config set project <PROJECT NAME> 
```

#### Get current project set
```
gcloud config get project
```

#### Get information about project
```
gcloud projects describe <PROJECT ID>
```

#### Gives a list of all APIs that are enabled in project
```
gcloud services list
```

### IAM
- Three roletypes
  - Basic roles, provides broader access to Google Cloud resources - Owner, Editor, Viewer
  - Predefined roles, provides granular access to specific Google Cloud resources.
  - Custom Roles, provides custom access to Google Cloud resources.

### Policies
- A policy defines members for each role

#### Enumerate all IAM policies on ORG-wide level
```
gcloud organizations list
gcloud organizations get-iam-policy <ORG ID>
```

#### Enumerate all IAM policies on folder level
```
gcloud resource-manager folders list --organization <ORG ID>
gcloud resource-manager folders get-iam-policy <FOLDER ID>
```

#### Enumerate all IAM policies on project level
```
gcloud projects list
gcloud projects get-iam-policy <PROJECT ID> 
```

#### Enumerate IAM policies of user on project level
```
gcloud projects list
gcloud projects get-iam-policy <PROJECT ID> --flatten="bindings[].members" --filter="bindings.members=user:<USER EMAIL>" --format="value(bindings.role)" 
```

#### Enumerate IAM policies of service account on project level
```
gcloud projects get-iam-policy <PROJECT ID> --flatten="bindings[].members" --filter="bindings.members=serviceAccount:<SERVICE ACCOUNT EMAIL>" --format="value(bindings.role)"
```

#### Oneliner to check permissions on all projects
```
gcloud projects list --format="value(PROJECT_NUMBER)" | while read project; do echo "\n [+] checking: $project\n" && gcloud projects get-iam-policy $project; done
```

#### Oneliner to check permissions of a user on all projects
```
GCUSER=<USER EMAIL>
gcloud projects list --format="value(PROJECT_NUMBER)" | while read project; do echo "\n [+] checking: $project\n" && gcloud projects get-iam-policy $project --flatten="bindings[].members" --filter="bindings.members=user:$GCUSER" --format="value(bindings.role)"; done
```

#### Oneliner to check permissions of a service account on all projects
```
GCUSER=<USER EMAIL>
gcloud projects list --format="value(PROJECT_NUMBER)" | while read project; do echo "\n [+] checking: $project\n" && gcloud projects get-iam-policy $project --flatten="bindings[].members" --filter="bindings.members=serviceAccount:$GCUSER" --format="value(bindings.role)"; done
```

#### Enumerate IAM policies of a resource
- No easy command to enumerate all accesible resources. But example syntax would be:
```
gcloud compute instances get-iam-policy <INSTANCE> --zone=<ZONE>
```

### Roles
#### Enumerate custom roles on project level
```
gcloud iam roles list --project <PROJECT ID>
```

#### List all permission in custom role
- Format of custom roles = `projects/<PROJECT NAME>/roles/<ROLE NAME>
- Use the last part of the `name`. 
```
gcloud iam roles describe <ROLE NAME> --project <PROJECT ID>
```

#### List all permissions of a role
- For example `roles/viewer`
```
gcloud iam roles describe <ROLE>
```

#### List permissions of service account
```
gcloud iam service-accounts list
gcloud iam service-accounts get-iam-policy <SERVICE ACCOUNT EMAIL>
```

#### Oneliner to check permissions of all service accounts
```
gcloud iam service-accounts list --format="value(email)" | while read serviceaccount; do echo "\n [+] checking: $serviceaccount\n" && gcloud iam service-accounts get-iam-policy $serviceaccount 2>/dev/null; done
```

#### Oneliner to check permissions of a user on all service accounts
```
GCUSER=<USER EMAIL>
gcloud iam service-accounts list --format="value(email)" | while read serviceaccount; do echo "\n [+] checking: $serviceaccount\n" && gcloud iam service-accounts get-iam-policy $serviceaccount --flatten="bindings[].members" --filter="bindings.members=user:$GCUSER" --format="value(bindings.role)" 2>/dev/null; done
```

### ORG Policies
#### List org policies on org level
```
gcloud resource-manager org-policies list --organization=<ORG ID>
```

#### List org policies on folder level
```
gcloud resource-manager org-policies list --folder=<FOLDER ID>
```

#### List org policies on project level
```
gcloud resource-manager org-policies list --project=<PROJECT ID>
```

### Bruterforce Permissions
- https://github.com/carlospolop/bf_my_gcp_permissions
- Open up `access_tokens.db` in `$HOME/.config/gcloud/` or `%APPDATA%\gcloud\`

#### Run the tool with access token
```
python3 bf_my_gcp_perms.py -t <ACCESS TOKEN>
```

#### Run the tool with .json
```

```

### Repos
#### Get source code repos available to user
```
gcloud source repos list
```

#### Clone repo to home dir
```
gcloud source repos clone <repo_name>
```

### Service accounts
- A service account always belongs to a project:

#### List service accounts on project level
```
gcloud iam service-accounts list
```

### Virtual machines
#### List compute instances on project level
```
gcloud compute instances list
```

### Networking
#### List networks
```
gcloud compute networks list
```

#### List subnets
```
gcloud compute networks subnets list
```

#### List VPN tunnels
```
gcloud compute vpn-tunnels list
```

#### List Interconnects (VPN)
```
gcloud compute interconnects list
```

### Function Apps
```
gcloud functions list
```

### Storage Buckets
#### List storage buckets
```
gsutil ls
```

#### List storage buckets recursively
```
gsutil ls -r gs://<bucket name>
```

#### Cat file
```
gsutil cat gs://<bucket name>/<FILE>
```

### Webapps and SQL
#### List webapps
```
gcloud app instances list
```

#### List SQL instances
```
gcloud sql instances list
gcloud spanner instances list
gcloud bigtable instances list
```

#### List SQL databases
```
gcloud sql databases list --instance <instance ID>
gcloud spanner databases list --instance <instance name>
```

#### Export SQL databases and buckets
- First copy buckets to local directory
```
gsutil cp gs://bucket-name/folder/ .
```

#### Create a new storage bucket, change perms, export SQL DB
```
gsutil mb gs://<googlestoragename>
gsutil acl ch -u <service account> gs://<googlestoragename>
gcloud sql export sql <sql instance name> gs://<googlestoragename>/sqldump.gz --database=<database name>
```

### Containers
```
gcloud container clusters list
```

#### GCP Kubernetes config file ~/.kube/config gets generated when you are authenticated with gcloud and run:
```
gcloud container clusters get-credentials <cluster name> --region <region>
```

#### Get cluster info
- If successful and the user has the correct permission the Kubernetes command below can be used to get cluster info:
```
kubectl cluster-info
```

## Serverless
#### List cloud functions
```
gcloud functions list
```

#### GCP functions log analysis 
- May get useful information from logs associated with GCP functions
```
gcloud functions describe <function name>
gcloud functions logs read <function name> --limit <number of lines>
```

#### GCP Cloud Run analysis
- May get useful information from descriptions such as environment variables.
```
gcloud run services list
gcloud run services describe <service-name>
gcloud run revisions describe --region=<region> <revision-name>
```

## Enumeration using Google Cloud API
- Service Endpoint : https://[ServiceName].googleapis.com
- Documentation: https://developers.google.com/apis-explorer
- Use the `--log-http` flag withing Gcloud CLI to see the requests it makes. Get the body, api endpoint etc and use it with Burp with other access token :)

#### Validate access token
```
curl https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=<ACCESS TOKEN>
```

#### Access Google API
```
curl -X Method -H “Authorization: Bearer $AccessToken” https://API-URL
```

## Automated Tools
### GCP_enum
- https://gitlab.com/gitlab-com/gl-security/threatmanagement/redteam/redteam-public/gcp_enum
- Login with account into the gcloud CLI.
```
bash gcp_enum.s
```

### GCP_Scanner
- https://github.com/google/gcp_scanner
- Uses all the credentials in the `$HOME/.config/gcloud` directory
```
python3 scanner.py -g "$HOME/.config/gcloud" -o .
``` 
