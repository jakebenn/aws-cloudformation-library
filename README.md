# AWS CloudFormation Library

**Python scripts for managing AWS CloudFormation stacks (including MFA support)**

## Summary
This Python 2.7 library provides a set of higher-level functions for spinning up and down AWS stacks. It is
designed to be used in scripts that control the creation and deletion of AWS stacks using CloudFormation, on projects 
that are comprised of microservices that each have their own stack.

## Motivation 
My preference or managing AWS CloudFormation stacks to create and delete them with a bash or Python script. 
This allows for more programmatic control of stack creation (e.g. uploading/removing S3 resources) and allows for the 
management of resources that don't have a CloudFormation equivalent. This library provides 
a set of reusable functions to speed-up the development of these scripts.

Because the permissions required to spin up and down CloudFormation stacks are so broad, the library includes 
support for multi-factor authentication. Ideally, the IAM account used to spin-up CloudFormation stacks (which often 
themselves include the creation of IAM resources) requires MFA for authentication, so that in the event a DevOps 
developer's machine is compromised--and his or her AWS access key is obtained--the attacker won't be able to gain 
access to AWS.

## Usage
The use case this library is designed to accomodate is a project containing multiple microservices, each of which 
has its own CloudFormation stack. The functions add a "microservice" tag to AWS resources to indicate which 
microservice it belongs to.

