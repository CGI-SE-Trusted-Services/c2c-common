var clover = new Object();

// JSON: {classes : [{name, id, sl, el,  methods : [{sl, el}, ...]}, ...]}
clover.pageData = {"classes":[{"el":100,"id":1072,"methods":[{"el":45,"sc":2,"sl":38},{"el":52,"sc":2,"sl":51},{"el":59,"sc":2,"sl":57},{"el":64,"sc":2,"sl":61},{"el":70,"sc":2,"sl":66},{"el":83,"sc":2,"sl":77},{"el":97,"sc":2,"sl":85}],"name":"HashedId","sl":29}]}

// JSON: {test_ID : {"methods": [ID1, ID2, ID3...], "name" : "testXXX() void"}, ...};
clover.testTargets = {"test_0":{"methods":[{"sl":51},{"sl":61},{"sl":66}],"name":"Verify that serializeCertWithoutSignature encodes the certificate without the signature correcly","pass":true,"statements":[{"sl":63},{"sl":68},{"sl":69}]},"test_119":{"methods":[{"sl":51},{"sl":61},{"sl":66}],"name":"Test to verifyCertificate","pass":true,"statements":[{"sl":63},{"sl":68},{"sl":69}]},"test_123":{"methods":[{"sl":38},{"sl":61}],"name":"Generate Signed CAM Message with and verify that all required fields are set and signature verifies.","pass":true,"statements":[{"sl":39},{"sl":43},{"sl":63}]},"test_124":{"methods":[{"sl":51},{"sl":61},{"sl":66}],"name":"Verify deserialization and serialization of reference ETSI Certificates works","pass":true,"statements":[{"sl":63},{"sl":68},{"sl":69}]},"test_126":{"methods":[{"sl":38},{"sl":77},{"sl":85}],"name":"Verify hashCode and equals","pass":true,"statements":[{"sl":39},{"sl":43},{"sl":79},{"sl":80},{"sl":81},{"sl":82},{"sl":87},{"sl":89},{"sl":91},{"sl":93},{"sl":94},{"sl":95},{"sl":96}]},"test_137":{"methods":[{"sl":51}],"name":"Verify the correct octet length of the HashedId3","pass":true,"statements":[]},"test_138":{"methods":[{"sl":38}],"name":"Verify IllegalArgumentException is thrown if to small hash value is given.","pass":true,"statements":[{"sl":39},{"sl":40}]},"test_14":{"methods":[{"sl":51},{"sl":61},{"sl":66}],"name":"Verify SignSecuredMessage using signer info type: certificate generates a valid signature and that verifySecuredMessage can verify it.","pass":true,"statements":[{"sl":63},{"sl":68},{"sl":69}]},"test_141":{"methods":[{"sl":38}],"name":"Verify toString","pass":true,"statements":[{"sl":39},{"sl":43}]},"test_148":{"methods":[{"sl":51},{"sl":66}],"name":"Verify getVerificationKey","pass":true,"statements":[{"sl":68},{"sl":69}]},"test_150":{"methods":[{"sl":38},{"sl":61}],"name":"Generate Enrollment Credential v1 for interoperability testing","pass":true,"statements":[{"sl":39},{"sl":43},{"sl":63}]},"test_16":{"methods":[{"sl":38},{"sl":77},{"sl":85}],"name":"Verify hashCode and equals","pass":true,"statements":[{"sl":39},{"sl":43},{"sl":79},{"sl":80},{"sl":81},{"sl":82},{"sl":87},{"sl":89},{"sl":90},{"sl":91},{"sl":93},{"sl":94},{"sl":95},{"sl":96}]},"test_162":{"methods":[{"sl":38},{"sl":61}],"name":"Generate Authorization Ticket and Signed Secured Message v1 for interoperability testing","pass":true,"statements":[{"sl":39},{"sl":43},{"sl":63}]},"test_179":{"methods":[{"sl":51},{"sl":57},{"sl":66}],"name":"Verify deserialization of a hash value","pass":true,"statements":[{"sl":58},{"sl":68},{"sl":69}]},"test_2":{"methods":[{"sl":51},{"sl":66}],"name":"Verify deserialization of EciesNistP256EncryptedKey","pass":true,"statements":[{"sl":68},{"sl":69}]},"test_20":{"methods":[{"sl":38},{"sl":61}],"name":"Generate Signed CAM Unrecognized Certificates Message and verify that all required fields are set and signature verifies.","pass":true,"statements":[{"sl":39},{"sl":43},{"sl":63}]},"test_203":{"methods":[{"sl":61}],"name":"Generate Signed DENM Message and verify that all required fields are set and signature verifies.","pass":true,"statements":[{"sl":63}]},"test_216":{"methods":[{"sl":38},{"sl":61},{"sl":85}],"name":"Generate Enrollment Credential with a digest as signer info","pass":true,"statements":[{"sl":39},{"sl":43},{"sl":63},{"sl":87},{"sl":89},{"sl":91},{"sl":93},{"sl":94},{"sl":96}]},"test_254":{"methods":[{"sl":61}],"name":"Verify serialization of RecipientInfo","pass":true,"statements":[{"sl":63}]},"test_26":{"methods":[{"sl":61}],"name":"Verify serialization","pass":true,"statements":[{"sl":63}]},"test_265":{"methods":[{"sl":38},{"sl":51},{"sl":61},{"sl":66},{"sl":85}],"name":"Verify that signAndEncryptSecureMessage and verifyAndDecryptSecuredMessage both encrypts and signs properly","pass":true,"statements":[{"sl":39},{"sl":43},{"sl":63},{"sl":68},{"sl":69},{"sl":87},{"sl":89},{"sl":91},{"sl":93},{"sl":94},{"sl":96}]},"test_266":{"methods":[{"sl":51},{"sl":57},{"sl":66}],"name":"Verify deserialization","pass":true,"statements":[{"sl":58},{"sl":68},{"sl":69}]},"test_28":{"methods":[{"sl":61}],"name":"Verify serialization","pass":true,"statements":[{"sl":63}]},"test_289":{"methods":[{"sl":38},{"sl":51},{"sl":61},{"sl":66}],"name":"Verify SignSecuredMessage using signer info type: certificate_digest_with_ecdsap256 generates a valid signature and that verifySecuredMessage can verify it.","pass":true,"statements":[{"sl":39},{"sl":43},{"sl":63},{"sl":68},{"sl":69}]},"test_300":{"methods":[{"sl":38},{"sl":77},{"sl":85}],"name":"Verify hashCode and equals","pass":true,"statements":[{"sl":39},{"sl":43},{"sl":79},{"sl":80},{"sl":81},{"sl":82},{"sl":87},{"sl":89},{"sl":91},{"sl":93},{"sl":94},{"sl":95},{"sl":96}]},"test_315":{"methods":[{"sl":51}],"name":"Verify the correct octet length of the HashedId8","pass":true,"statements":[]},"test_327":{"methods":[{"sl":61}],"name":"Verify serialization","pass":true,"statements":[{"sl":63}]},"test_350":{"methods":[{"sl":51},{"sl":61},{"sl":66}],"name":"Verify signature of reference secure messages from interoperabiltity site at https://werkzeug.dcaiti.tu-berlin.de/etsi/ts103097/","pass":true,"statements":[{"sl":63},{"sl":68},{"sl":69}]},"test_362":{"methods":[{"sl":38}],"name":"Verify toString","pass":true,"statements":[{"sl":39},{"sl":43}]},"test_366":{"methods":[{"sl":61}],"name":"Verify getEncoded","pass":true,"statements":[{"sl":63}]},"test_377":{"methods":[{"sl":57}],"name":"Verify the constructors and getters","pass":true,"statements":[{"sl":58}]},"test_387":{"methods":[{"sl":38},{"sl":51},{"sl":61},{"sl":66},{"sl":85}],"name":"verify that encryptSecureMessage and decryptSecureMessage encrypts and decrypts correctly","pass":true,"statements":[{"sl":39},{"sl":43},{"sl":63},{"sl":68},{"sl":69},{"sl":87},{"sl":89},{"sl":91},{"sl":93},{"sl":94},{"sl":95},{"sl":96}]},"test_392":{"methods":[{"sl":38}],"name":"Verify the constructors and getters","pass":true,"statements":[{"sl":39},{"sl":43}]},"test_394":{"methods":[{"sl":38},{"sl":61},{"sl":85}],"name":"Generate Authorization Ticket with a digest as signer info","pass":true,"statements":[{"sl":39},{"sl":43},{"sl":63},{"sl":87},{"sl":89},{"sl":91},{"sl":93},{"sl":94},{"sl":96}]},"test_42":{"methods":[{"sl":38},{"sl":57}],"name":"Verify the correct octet length of the HashedId3","pass":true,"statements":[{"sl":39},{"sl":43},{"sl":58}]},"test_50":{"methods":[{"sl":51},{"sl":66}],"name":"Verify deserialization","pass":true,"statements":[{"sl":68},{"sl":69}]},"test_56":{"methods":[{"sl":51},{"sl":66}],"name":"Verify that it is possible to parse a SecureMessage generate by interoperability site at https://werkzeug.dcaiti.tu-berlin.de/etsi/ts103097/","pass":true,"statements":[{"sl":68},{"sl":69}]},"test_57":{"methods":[{"sl":38},{"sl":51},{"sl":61},{"sl":66},{"sl":85}],"name":"Verify that findRecipientInfo find correct RecipientInfo","pass":true,"statements":[{"sl":39},{"sl":43},{"sl":63},{"sl":68},{"sl":69},{"sl":87},{"sl":89},{"sl":91},{"sl":93},{"sl":94},{"sl":95},{"sl":96}]},"test_59":{"methods":[{"sl":38},{"sl":61}],"name":"Verify serialization of a hash value","pass":true,"statements":[{"sl":39},{"sl":43},{"sl":63}]},"test_63":{"methods":[{"sl":51},{"sl":66}],"name":"Verify deserialization","pass":true,"statements":[{"sl":68},{"sl":69}]}}

// JSON: { lines : [{tests : [testid1, testid2, testid3, ...]}, ...]};
clover.srcFileLines = [[], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [123, 289, 265, 216, 42, 20, 57, 392, 59, 141, 300, 387, 394, 16, 150, 138, 126, 362, 162], [123, 289, 265, 216, 42, 20, 57, 392, 59, 141, 300, 387, 394, 16, 150, 138, 126, 362, 162], [138], [], [], [123, 289, 265, 216, 42, 20, 57, 392, 59, 141, 300, 387, 394, 16, 150, 126, 362, 162], [], [], [], [], [], [], [], [179, 266, 137, 119, 289, 265, 315, 148, 0, 57, 14, 56, 387, 124, 50, 350, 63, 2], [], [], [], [], [], [179, 266, 377, 42], [179, 266, 377, 42], [], [], [123, 119, 254, 289, 265, 216, 327, 366, 0, 20, 57, 28, 14, 59, 203, 387, 124, 394, 150, 350, 162, 26], [], [123, 119, 254, 289, 265, 216, 327, 366, 0, 20, 57, 28, 14, 59, 203, 387, 124, 394, 150, 350, 162, 26], [], [], [179, 266, 119, 289, 265, 148, 0, 57, 14, 56, 387, 124, 50, 350, 63, 2], [], [179, 266, 119, 289, 265, 148, 0, 57, 14, 56, 387, 124, 50, 350, 63, 2], [179, 266, 119, 289, 265, 148, 0, 57, 14, 56, 387, 124, 50, 350, 63, 2], [], [], [], [], [], [], [], [300, 16, 126], [], [300, 16, 126], [300, 16, 126], [300, 16, 126], [300, 16, 126], [], [], [265, 216, 57, 300, 387, 394, 16, 126], [], [265, 216, 57, 300, 387, 394, 16, 126], [], [265, 216, 57, 300, 387, 394, 16, 126], [16], [265, 216, 57, 300, 387, 394, 16, 126], [], [265, 216, 57, 300, 387, 394, 16, 126], [265, 216, 57, 300, 387, 394, 16, 126], [57, 300, 387, 16, 126], [265, 216, 57, 300, 387, 394, 16, 126], [], [], [], []]
