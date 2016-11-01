# AWS CloudFormation Library

**Python scripts for managing AWS CloudFormation stacks (including MFA support)**

## Summary
This Python 2.7 library provides a set of higher-level functions for spinning up and down AWS stacks. It is
designed to be used in scripts that control the creation and deletion of AWS stacks using CloudFormation. It is 
intended to by used for projects that are comprised of microservices that each have their own stack.

## Motivation 
My preference or managing AWS CloudFormation stacks to create and delete them with a bash or Python script. 
This allows for more programmatic control of stack creation (e.g. uploading/removing S3 resources) and allows for the 
management of resources that don't have a CloudFormation equivalent (there are a few that don't). This library provides 
a set of reusable functions to speed-up the development process of these scripts.

Because the permissions required to spin up and down CloudFormation stacks are so broad, the library includes 
support for multi-factor authentication. Ideally, the IAM account used to spin-up CloudFormation stacks (which often 
themselves include the creation of IAM resources) requires MFA for authentication, so that in the event a DevOps 
developer's machine is compromised--and his or her AWS access key is obtained--the attacker won't be able to gain
access to AWS.