// This script is meant as an incident response security control when an S3 bycket policy uses widlcards that could result in data breach. 

// Load the SDK for JavaScript
var AWS = require('aws-sdk');


// Create S3 service object
s3 = new AWS.S3({apiVersion: '2006-03-01'});
 
// list buckets
 
 s3.listBuckets(function(err, data) {
   if (err) console.log(err, err.stack); // an error occurred
   else     // console.log(data);           // successful response
    
       
       
    var index = 0, length = Object.keys(data.Buckets).length;
        for (index; index < length; index++) {
        const buckName = data.Buckets[index].Name; 
             
        // The following example retrieves an object for an S3 bucket. */
           
            
            var bucketParams = {Bucket: buckName};
            // call S3 to retrieve policy for selected bucket
            s3.getBucketPolicy(bucketParams, function(err, data) {
              if (err) {
                console.log("No bucket policy");
              } else if (data) {
                
                var buckPolicy = JSON.parse(data.Policy);  
                
                   var policyCounter = 0, policyLength = Object.keys(buckPolicy.Statement).length;
                    for (policyCounter; policyCounter < policyLength; policyCounter++) {
                      
                        if(buckPolicy.Statement[policyCounter].Principal == '*' ) {
                            console.log("WARNING! THE BUCKET " + buckName + " HAS A PRINCIPAL OF " + buckPolicy.Statement[policyCounter].Principal + " FOUND ON " + Date.now());
                        } else{
                            console.log('No * principals found in the Bucket policies')
                        }
                        
                        if('*' == buckPolicy.Statement[0].Action) {
                            console.log("WARNING! THE BUCKET " + buckName + " HAS AN ACTION OF " + buckPolicy.Statement[policyCounter].Action + " FOUND ON " + Date.now());
                        } else{
                            console.log('No * ACTIONS found in the Bucket policies')
                        }
                        
                         if('*' == buckPolicy.Statement[0].Action && buckPolicy.Statement[policyCounter].Principal == '*' ) {
                            console.log("WARNING! THE BUCKET " + buckName + " has an ACTION of " + buckPolicy.Statement[policyCounter].Action + " and a PRINCIPAL of " + buckPolicy.Statement[policyCounter].Principal + " FOUND ON " + Date.now());
                             
                             var params = {
                                  Bucket: buckName /* required */
                                };
                                s3.getBucketAcl(params, function(err, data) {
                                  if (err) console.log(err, err.stack); // an error occurred
                                  else     console.log(data);           // successful response
                                
                                 console.log(data.Owner.DisplayName);    
                                    
                                    var params = {
                                          Bucket: buckName, 
                                          Policy: "{\"Version\": \"2012-10-17\", \"Statement\": [{ \"Sid\": \"id-1\",\"Effect\": \"Deny\",\"Principal\": {\"AWS\": \"arn:aws:iam::<account id>:<user or object=to owner>\"}, \"Action\": [ \"*\"], \"Resource\": [\"arn:aws:s3:::< your bucket>\" ] } ]}"
                                         };
                                         s3.putBucketPolicy(params, function(err, data) {
                                           if (err) console.log(err, err.stack); // an error occurred
                                           else     console.log(data);           // successful response
                                         });
                                        
                                });
                            
                        } 
                    }
                
              }else {
                  console.log('foo bar');
              }
            });
        }
 });



