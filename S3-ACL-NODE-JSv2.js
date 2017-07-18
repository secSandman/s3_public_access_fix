// This script is meant as an incident response security control. AWS CloudWatch is meant to detect and create a security event which triggers this function. Therefore this assumes that a breach in security compliance has already occured. Assuming a breach in compliance has occured this script wil lauto automatically respond and configure AWS S3 Access Control List to restrct permissions to your data to private. This helps mitigate the length of time your private data being hosted publicly over the internet. 


// Load the SDK for JavaScript
var AWS = require('aws-sdk');


// Create S3 service object
s3 = new AWS.S3({apiVersion: '2006-03-01'});


// running the audit as a cron job 
var cron = require('node-cron');
 
cron.schedule('* * * * *', function(){
  
// Lists all buckets 
s3.listBuckets(function(err, data) {
  if (err) console.log(err, err.stack); // an error occurred
  else     // Testing parsing the objects in the array 
           // Testing console.log(data.Buckets);
           // Testing the array key counter 
           // Testing console.log(Object.keys(data.Buckets).length);
        
           // #1 Find all the buckets in the account and search for buckets with Grantees index. 
           var index = 0, length = Object.keys(data.Buckets).length;
           for (index; index < length; index++) {
           const buckName = data.Buckets[index].Name; //Get the bucket ACLs using the Bucket names from the data.Buckets array 
           // Use this to test bucket key position. console.log(data.Buckets[index].Name);  
               
        // #2 call S3 to retrieve policy for selected bucket
        // #2 tell aws which bucket you want using the index loop
           var bucketParams = {Bucket: data.Buckets[index].Name};
                
                s3.getBucketAcl(bucketParams, function(err, data) {
                  if (err) {
                    console.log("Error occured while getting Bucket ACL", err);
                  
                  // #3 Grant objects are referenced using numbered key index. When 0 exists there are owner permissions, when 1 exists there are public permissions, when 2 exists there log permissons
                  } else if (Object.keys(data.Grants)[1] == 1) {
                      
                             // console.log('This means there is an array for the the Manage public permissions keys');
                            // console.log(Object.keys(data.Grants)); // Testing Where an index of 1 results in public permisisons 
                           // console.log(data.Grants[1]); // Testing Here is an example of the public permissions
                           
                        // #3 When we put new ACL, we remove the Grantee Public of inedx 1 within the array 
                       // #3 Then we set the Grants and Owner back to the existing Owner. Typically there is at least one grant for the owner. 
                      // #3 This code does not account for multiple pre-existing Grantees. If Grantees >1 then we would need to dynamically add more Grantees keys to the Grantee object. In this version of the code if Grantees is >1 all Grantees will lose access and the Grantees will need to be manually added. 
                      
                        var ACLparams = {
                              Bucket: buckName, 
                              AccessControlPolicy: {
                                    Grants: [
                                      {
                                        Grantee: {
                                          Type: 'CanonicalUser', 
                                          DisplayName: data.Owner.DisplayName,
                                          ID: data.Owner.ID
                                        },
                                        Permission: 'FULL_CONTROL'
                                      }
                                    ], 
                                    Owner: {
                                      DisplayName: data.Owner.DisplayName,
                                      ID: data.Owner.ID
                                    }
                                }
                            };
                            
                      //#4 Pass the new ACL to the putBucketACL argument 
                             s3.putBucketAcl(ACLparams, function(err, data) {
                               if (err) console.log(err, err.stack); // an error occurred
                               else     
                                   console.log('WARNING!! HIGH RISK PUBLIC ACCESS CONFIGURED ON ' + JSON.stringify(buckName) + ' IN AN AWS ACCOUNT MEANT FOR INTERNAL ACCESS. EVENT FOUND ON  ' + Date.now() + '. PUBLIC ACCESS HAS BEEN DISABLED');  // successful response
                             });
                      
                      //# 5 Timestamp of the audit. This timestamp can be sent to /var/log/messages and you can configure AWSlogs agent to forward these timestamps to a central repo for later legal and auditing purposes.                        
                  } else{
                            console.log('NO PUBLIC PERMISSIONS FOUND IN ' + JSON.stringify(buckName) + ' BUCKET ON ' + Date.now());
                        }    
                    });   
            }
    });
 
});
