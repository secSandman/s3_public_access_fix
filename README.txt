# S3 Public READ Audit and Incident Response 

This script scans for aws s3 buckets and finds buckets configured with public read. It then takes corrective action to remove public read. This script should only be used when in aws accounts where public s3 access is strictly forbidden. Where public access is allowed this script will cause an outage. There is no logic to differentiate between what buckets are approved to be public and which are not. Therefore it is only okay to run this script when in a internal account only where you would never expect to see public access. Otherwise you could modify the code to describe S3 tags and use a data classification tag to invoke a response. Enjoy

# About

The app is written in Node.JS

Currently it runs as a cron job every minute of every hour etc. 

However, the same code can be run as a lambda function and use event driven triggers such as aws config.

I attempted to use Cloudwatch however I was unable to capture logs at the bucket acl level. 

If you figure this out let me know because ideally this would trigger the lambda function.


I left the code with my inline comments to help folks understand 

I also left some example console.logs in the code to illustrate where you could log out to /var/logs/messages etc. and forward on with aws logs agent. These logs could be used for audit and legal purposes if a security incident arises. Currently the user action cannot be logged. This needs to be picked up another using aws logs mechanisms.


# Disclaimer

Service does not us any prepared statements

Service has not been validated by any security tooling

Product assumed as-is as indicated in the License.txt