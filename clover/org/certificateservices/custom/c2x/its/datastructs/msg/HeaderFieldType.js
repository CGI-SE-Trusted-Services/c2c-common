var clover = new Object();

// JSON: {classes : [{name, id, sl, el,  methods : [{sl, el}, ...]}, ...]}
clover.pageData = {"classes":[{"el":70,"id":2968,"methods":[{"el":52,"sc":2,"sl":50},{"el":56,"sc":2,"sl":54},{"el":68,"sc":2,"sl":61}],"name":"HeaderFieldType","sl":37}]}

// JSON: {test_ID : {"methods": [ID1, ID2, ID3...], "name" : "testXXX() void"}, ...};
clover.testTargets = {"test_123":{"methods":[{"sl":54}],"name":"Generate Signed CAM Message with and verify that all required fields are set and signature verifies.","pass":true,"statements":[{"sl":55}]},"test_136":{"methods":[{"sl":61}],"name":"Verify that TrailerFieldType.getByValue returns encryption_parameters for 130","pass":true,"statements":[{"sl":62},{"sl":63},{"sl":64}]},"test_14":{"methods":[{"sl":54},{"sl":61}],"name":"Verify SignSecuredMessage using signer info type: certificate generates a valid signature and that verifySecuredMessage can verify it.","pass":true,"statements":[{"sl":55},{"sl":62},{"sl":63},{"sl":64}]},"test_162":{"methods":[{"sl":54}],"name":"Generate Authorization Ticket and Signed Secured Message v1 for interoperability testing","pass":true,"statements":[{"sl":55}]},"test_166":{"methods":[{"sl":61}],"name":"Verify that TrailerFieldType.getByValue returns generation_time_confidence for 1","pass":true,"statements":[{"sl":62},{"sl":63},{"sl":64}]},"test_167":{"methods":[{"sl":61}],"name":"Verify that TrailerFieldType.getByValue returns request_unrecognized_certificate for 4","pass":true,"statements":[{"sl":62},{"sl":63},{"sl":64}]},"test_171":{"methods":[{"sl":54}],"name":"Verify that addHeader adds the header value in correct order","pass":true,"statements":[{"sl":55}]},"test_185":{"methods":[{"sl":54}],"name":"Verify that generation_time_confidence has bytevalue 1","pass":true,"statements":[{"sl":55}]},"test_186":{"methods":[{"sl":54}],"name":"Verify that recipient_info has bytevalue 129","pass":true,"statements":[{"sl":55}]},"test_20":{"methods":[{"sl":54}],"name":"Generate Signed CAM Unrecognized Certificates Message and verify that all required fields are set and signature verifies.","pass":true,"statements":[{"sl":55}]},"test_203":{"methods":[{"sl":54}],"name":"Generate Signed DENM Message and verify that all required fields are set and signature verifies.","pass":true,"statements":[{"sl":55}]},"test_213":{"methods":[{"sl":61}],"name":"Verify that TrailerFieldType.getByValue returns generation_location for 3","pass":true,"statements":[{"sl":62},{"sl":63},{"sl":64}]},"test_241":{"methods":[{"sl":61}],"name":"Verify that TrailerFieldType.getByValue returns signer_info for 128","pass":true,"statements":[{"sl":62},{"sl":63},{"sl":64}]},"test_26":{"methods":[{"sl":54}],"name":"Verify serialization","pass":true,"statements":[{"sl":55}]},"test_264":{"methods":[{"sl":54}],"name":"Verify that signer_info has bytevalue 128","pass":true,"statements":[{"sl":55}]},"test_265":{"methods":[{"sl":54},{"sl":61}],"name":"Verify that signAndEncryptSecureMessage and verifyAndDecryptSecuredMessage both encrypts and signs properly","pass":true,"statements":[{"sl":55},{"sl":62},{"sl":63},{"sl":64}]},"test_275":{"methods":[{"sl":54}],"name":"Verify that expiration has bytevalue 2","pass":true,"statements":[{"sl":55}]},"test_289":{"methods":[{"sl":54},{"sl":61}],"name":"Verify SignSecuredMessage using signer info type: certificate_digest_with_ecdsap256 generates a valid signature and that verifySecuredMessage can verify it.","pass":true,"statements":[{"sl":55},{"sl":62},{"sl":63},{"sl":64}]},"test_314":{"methods":[{"sl":54}],"name":"Verify that request_unrecognized_certificate has bytevalue 4","pass":true,"statements":[{"sl":55}]},"test_320":{"methods":[{"sl":54}],"name":"Verify that message_type has bytevalue 5","pass":true,"statements":[{"sl":55}]},"test_322":{"methods":[{"sl":61}],"name":"Verify that TrailerFieldType.getByValue returns expiration for 2","pass":true,"statements":[{"sl":62},{"sl":63},{"sl":64}]},"test_327":{"methods":[{"sl":54}],"name":"Verify serialization","pass":true,"statements":[{"sl":55}]},"test_337":{"methods":[{"sl":61}],"name":"Verify that TrailerFieldType.getByValue returns message_type for 5","pass":true,"statements":[{"sl":62},{"sl":63},{"sl":64}]},"test_349":{"methods":[{"sl":54}],"name":"Verify that generation_location has bytevalue 3","pass":true,"statements":[{"sl":55}]},"test_350":{"methods":[{"sl":54},{"sl":61}],"name":"Verify signature of reference secure messages from interoperabiltity site at https://werkzeug.dcaiti.tu-berlin.de/etsi/ts103097/","pass":true,"statements":[{"sl":55},{"sl":62},{"sl":63},{"sl":64}]},"test_366":{"methods":[{"sl":54}],"name":"Verify getEncoded","pass":true,"statements":[{"sl":55}]},"test_38":{"methods":[{"sl":61}],"name":"Verify that TrailerFieldType.getByValue returns recipient_info for 129","pass":true,"statements":[{"sl":62},{"sl":63},{"sl":64}]},"test_387":{"methods":[{"sl":54},{"sl":61}],"name":"verify that encryptSecureMessage and decryptSecureMessage encrypts and decrypts correctly","pass":true,"statements":[{"sl":55},{"sl":62},{"sl":63},{"sl":64}]},"test_5":{"methods":[{"sl":61}],"name":"Verify that TrailerFieldType.getByValue returns generation_time for 0","pass":true,"statements":[{"sl":62},{"sl":63},{"sl":64}]},"test_50":{"methods":[{"sl":61}],"name":"Verify deserialization","pass":true,"statements":[{"sl":62},{"sl":63},{"sl":64}]},"test_52":{"methods":[{"sl":54}],"name":"Verify that encryption_parameters has bytevalue 130","pass":true,"statements":[{"sl":55}]},"test_53":{"methods":[{"sl":54}],"name":"Verify that generation_time has bytevalue 0","pass":true,"statements":[{"sl":55}]},"test_56":{"methods":[{"sl":61}],"name":"Verify that it is possible to parse a SecureMessage generate by interoperability site at https://werkzeug.dcaiti.tu-berlin.de/etsi/ts103097/","pass":true,"statements":[{"sl":62},{"sl":63},{"sl":64}]},"test_63":{"methods":[{"sl":61}],"name":"Verify deserialization","pass":true,"statements":[{"sl":62},{"sl":63},{"sl":64}]},"test_71":{"methods":[{"sl":54}],"name":"Verify that serializeDataToBeSignedInSecuredMessage serializes according to signature verification it ETSI specifification","pass":true,"statements":[{"sl":55}]}}

// JSON: { lines : [{tests : [testid1, testid2, testid3, ...]}, ...]};
clover.srcFileLines = [[], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [123, 186, 185, 349, 289, 314, 265, 171, 327, 366, 20, 14, 264, 203, 387, 320, 52, 350, 275, 162, 53, 26, 71], [123, 186, 185, 349, 289, 314, 265, 171, 327, 366, 20, 14, 264, 203, 387, 320, 52, 350, 275, 162, 53, 26, 71], [], [], [], [], [], [289, 265, 5, 337, 14, 213, 56, 387, 322, 50, 241, 167, 166, 350, 38, 63, 136], [289, 265, 5, 337, 14, 213, 56, 387, 322, 50, 241, 167, 166, 350, 38, 63, 136], [289, 265, 5, 337, 14, 213, 56, 387, 322, 50, 241, 167, 166, 350, 38, 63, 136], [289, 265, 5, 337, 14, 213, 56, 387, 322, 50, 241, 167, 166, 350, 38, 63, 136], [], [], [], [], [], []]
