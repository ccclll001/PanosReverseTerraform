# PanosReverseTerraform
Get Terraform files from Panorama/Firewall configuration XML

## Web App (Cloud Deploy)

**Live URL**: [https://panos2terraform-262936-7-1259747719.sh.run.tcloudbase.com](https://panos2terraform-262936-7-1259747719.sh.run.tcloudbase.com)

Upload your `running-config.xml`, get `.tf` files back as a zip download.

- Supports Panorama (device-group) and standalone Firewall (vsys) configs
- Deployed on Tencent CloudBase CloudRun (container mode)

## How to use (Local CLI)

Run xml2terraform.py in the same directory as a Panorama running-config.xml file

Get main.tf with all the security Policies in the configuration in their respective Device Group and Rulebase

## NOTE: 
if you have dynamic object groups this program WONT work and WILL crash.
## Supports:

Security Policies
Address objects (All types)
Address groups (statics)
# Pending:

Address groups (dynamic)

## Deployment

- **Platform**: Tencent CloudBase
- **Service**: CloudRun (container)
- **Environment**: `cccl-d9gjv76i36dcafa55`
- **Resources**: 0.5 CPU / 1 GB RAM / Min 1 instance

### About terraformer

Ive seen that theres also this tool named terraformer (https://panos.pan.dev/docs/automation/terraformer_qs) that connect directly to the panorama/firewall to also do this kind of job, but it has let me down due to several limitations thats why im still working on tihis


