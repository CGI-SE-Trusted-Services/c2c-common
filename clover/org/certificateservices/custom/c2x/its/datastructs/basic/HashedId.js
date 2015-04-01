var clover = new Object();

// JSON: {classes : [{name, id, sl, el,  methods : [{sl, el}, ...]}, ...]}
clover.pageData = {"classes":[{"el":100,"id":1072,"methods":[{"el":45,"sc":2,"sl":38},{"el":52,"sc":2,"sl":51},{"el":59,"sc":2,"sl":57},{"el":64,"sc":2,"sl":61},{"el":70,"sc":2,"sl":66},{"el":83,"sc":2,"sl":77},{"el":97,"sc":2,"sl":85}],"name":"HashedId","sl":29}]}

// JSON: {test_ID : {"methods": [ID1, ID2, ID3...], "name" : "testXXX() void"}, ...};
clover.testTargets = {"test_1":{"methods":[{"sl":38},{"sl":61}],"name":"Generate Signed CAM Unrecognized Certificates Message and verify that all required fields are set and signature verifies.","pass":true,"statements":[{"sl":39},{"sl":43},{"sl":63}]},"test_112":{"methods":[{"sl":51},{"sl":61},{"sl":66}],"name":"Test to verifyCertificate","pass":true,"statements":[{"sl":63},{"sl":68},{"sl":69}]},"test_116":{"methods":[{"sl":38},{"sl":61},{"sl":85}],"name":"Generate Authorization Ticket with a digest as signer info","pass":true,"statements":[{"sl":39},{"sl":43},{"sl":63},{"sl":87},{"sl":89},{"sl":91},{"sl":93},{"sl":94},{"sl":96}]},"test_125":{"methods":[{"sl":51},{"sl":61},{"sl":66}],"name":"Verify that serializeCertWithoutSignature encodes the certificate without the signature correcly","pass":true,"statements":[{"sl":63},{"sl":68},{"sl":69}]},"test_13":{"methods":[{"sl":61}],"name":"Generate Signed DENM Message and verify that all required fields are set and signature verifies.","pass":true,"statements":[{"sl":63}]},"test_133":{"methods":[{"sl":61}],"name":"Verify getEncoded","pass":true,"statements":[{"sl":63}]},"test_138":{"methods":[{"sl":51},{"sl":66}],"name":"Verify deserialization","pass":true,"statements":[{"sl":68},{"sl":69}]},"test_148":{"methods":[{"sl":51},{"sl":61},{"sl":66}],"name":"Verify SignSecuredMessage using signer info type: certificate generates a valid signature and that verifySecuredMessage can verify it.","pass":true,"statements":[{"sl":63},{"sl":68},{"sl":69}]},"test_151":{"methods":[{"sl":38},{"sl":51},{"sl":61},{"sl":66},{"sl":85}],"name":"Verify that findRecipientInfo find correct RecipientInfo","pass":true,"statements":[{"sl":39},{"sl":43},{"sl":63},{"sl":68},{"sl":69},{"sl":87},{"sl":89},{"sl":91},{"sl":93},{"sl":94},{"sl":95},{"sl":96}]},"test_154":{"methods":[{"sl":61}],"name":"Verify serialization","pass":true,"statements":[{"sl":63}]},"test_159":{"methods":[{"sl":51},{"sl":66}],"name":"Verify deserialization of EciesNistP256EncryptedKey","pass":true,"statements":[{"sl":68},{"sl":69}]},"test_16":{"methods":[{"sl":51},{"sl":66}],"name":"Verify getVerificationKey","pass":true,"statements":[{"sl":68},{"sl":69}]},"test_168":{"methods":[{"sl":51},{"sl":57},{"sl":66}],"name":"Verify deserialization of a hash value","pass":true,"statements":[{"sl":58},{"sl":68},{"sl":69}]},"test_183":{"methods":[{"sl":51},{"sl":57},{"sl":66}],"name":"Verify deserialization","pass":true,"statements":[{"sl":58},{"sl":68},{"sl":69}]},"test_186":{"methods":[{"sl":38},{"sl":77},{"sl":85}],"name":"Verify hashCode and equals","pass":true,"statements":[{"sl":39},{"sl":43},{"sl":79},{"sl":80},{"sl":81},{"sl":82},{"sl":87},{"sl":89},{"sl":91},{"sl":93},{"sl":94},{"sl":95},{"sl":96}]},"test_19":{"methods":[{"sl":61}],"name":"Verify serialization of RecipientInfo","pass":true,"statements":[{"sl":63}]},"test_227":{"methods":[{"sl":38}],"name":"Verify the constructors and getters","pass":true,"statements":[{"sl":39},{"sl":43}]},"test_232":{"methods":[{"sl":38},{"sl":51},{"sl":61},{"sl":66},{"sl":85}],"name":"Verify that signAndEncryptSecureMessage and verifyAndDecryptSecuredMessage both encrypts and signs properly","pass":true,"statements":[{"sl":39},{"sl":43},{"sl":63},{"sl":68},{"sl":69},{"sl":87},{"sl":89},{"sl":91},{"sl":93},{"sl":94},{"sl":96}]},"test_239":{"methods":[{"sl":51},{"sl":61},{"sl":66}],"name":"Verify deserialization and serialization of reference ETSI Certificates works","pass":true,"statements":[{"sl":63},{"sl":68},{"sl":69}]},"test_241":{"methods":[{"sl":61}],"name":"Verify serialization","pass":true,"statements":[{"sl":63}]},"test_254":{"methods":[{"sl":57}],"name":"Verify the constructors and getters","pass":true,"statements":[{"sl":58}]},"test_26":{"methods":[{"sl":38},{"sl":61}],"name":"Generate Authorization Ticket and Signed Secured Message v1 for interoperability testing","pass":true,"statements":[{"sl":39},{"sl":43},{"sl":63}]},"test_266":{"methods":[{"sl":51}],"name":"Verify the correct octet length of the HashedId8","pass":true,"statements":[]},"test_27":{"methods":[{"sl":38},{"sl":51},{"sl":61},{"sl":66}],"name":"Verify SignSecuredMessage using signer info type: certificate_digest_with_ecdsap256 generates a valid signature and that verifySecuredMessage can verify it.","pass":true,"statements":[{"sl":39},{"sl":43},{"sl":63},{"sl":68},{"sl":69}]},"test_277":{"methods":[{"sl":38},{"sl":61}],"name":"Generate Signed CAM Message with and verify that all required fields are set and signature verifies.","pass":true,"statements":[{"sl":39},{"sl":43},{"sl":63}]},"test_286":{"methods":[{"sl":51}],"name":"Verify the correct octet length of the HashedId3","pass":true,"statements":[]},"test_32":{"methods":[{"sl":38}],"name":"Verify toString","pass":true,"statements":[{"sl":39},{"sl":43}]},"test_336":{"methods":[{"sl":38},{"sl":61}],"name":"Generate Enrollment Credential v1 for interoperability testing","pass":true,"statements":[{"sl":39},{"sl":43},{"sl":63}]},"test_357":{"methods":[{"sl":38},{"sl":51},{"sl":61},{"sl":66},{"sl":85}],"name":"verify that encryptSecureMessage and decryptSecureMessage encrypts and decrypts correctly","pass":true,"statements":[{"sl":39},{"sl":43},{"sl":63},{"sl":68},{"sl":69},{"sl":87},{"sl":89},{"sl":91},{"sl":93},{"sl":94},{"sl":95},{"sl":96}]},"test_363":{"methods":[{"sl":38}],"name":"Verify toString","pass":true,"statements":[{"sl":39},{"sl":43}]},"test_372":{"methods":[{"sl":38},{"sl":61},{"sl":85}],"name":"Generate Enrollment Credential with a digest as signer info","pass":true,"statements":[{"sl":39},{"sl":43},{"sl":63},{"sl":87},{"sl":89},{"sl":91},{"sl":93},{"sl":94},{"sl":96}]},"test_376":{"methods":[{"sl":51},{"sl":61},{"sl":66}],"name":"Verify signature of reference secure messages from interoperabiltity site at https://werkzeug.dcaiti.tu-berlin.de/etsi/ts103097/","pass":true,"statements":[{"sl":63},{"sl":68},{"sl":69}]},"test_379":{"methods":[{"sl":38}],"name":"Verify IllegalArgumentException is thrown if to small hash value is given.","pass":true,"statements":[{"sl":39},{"sl":40}]},"test_395":{"methods":[{"sl":38},{"sl":77},{"sl":85}],"name":"Verify hashCode and equals","pass":true,"statements":[{"sl":39},{"sl":43},{"sl":79},{"sl":80},{"sl":81},{"sl":82},{"sl":87},{"sl":89},{"sl":90},{"sl":91},{"sl":93},{"sl":94},{"sl":95},{"sl":96}]},"test_4":{"methods":[{"sl":38},{"sl":77},{"sl":85}],"name":"Verify hashCode and equals","pass":true,"statements":[{"sl":39},{"sl":43},{"sl":79},{"sl":80},{"sl":81},{"sl":82},{"sl":87},{"sl":89},{"sl":91},{"sl":93},{"sl":94},{"sl":95},{"sl":96}]},"test_44":{"methods":[{"sl":38},{"sl":57}],"name":"Verify the correct octet length of the HashedId3","pass":true,"statements":[{"sl":39},{"sl":43},{"sl":58}]},"test_6":{"methods":[{"sl":51},{"sl":66}],"name":"Verify that it is possible to parse a SecureMessage generate by interoperability site at https://werkzeug.dcaiti.tu-berlin.de/etsi/ts103097/","pass":true,"statements":[{"sl":68},{"sl":69}]},"test_64":{"methods":[{"sl":38},{"sl":61}],"name":"Verify serialization of a hash value","pass":true,"statements":[{"sl":39},{"sl":43},{"sl":63}]},"test_87":{"methods":[{"sl":51},{"sl":66}],"name":"Verify deserialization","pass":true,"statements":[{"sl":68},{"sl":69}]},"test_98":{"methods":[{"sl":61}],"name":"Verify serialization","pass":true,"statements":[{"sl":63}]}}

// JSON: { lines : [{tests : [testid1, testid2, testid3, ...]}, ...]};
clover.srcFileLines = [[], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [277, 357, 26, 232, 227, 372, 379, 336, 363, 44, 64, 1, 27, 395, 186, 32, 116, 4, 151], [277, 357, 26, 232, 227, 372, 379, 336, 363, 44, 64, 1, 27, 395, 186, 32, 116, 4, 151], [379], [], [], [277, 357, 26, 232, 227, 372, 336, 363, 44, 64, 1, 27, 395, 186, 32, 116, 4, 151], [], [], [], [], [], [], [], [357, 239, 138, 286, 6, 159, 232, 183, 266, 16, 27, 125, 168, 112, 148, 151, 376, 87], [], [], [], [], [], [183, 44, 168, 254], [183, 44, 168, 254], [], [], [277, 357, 239, 154, 26, 232, 98, 372, 336, 133, 13, 64, 1, 27, 125, 241, 112, 116, 148, 151, 376, 19], [], [277, 357, 239, 154, 26, 232, 98, 372, 336, 133, 13, 64, 1, 27, 125, 241, 112, 116, 148, 151, 376, 19], [], [], [357, 239, 138, 6, 159, 232, 183, 16, 27, 125, 168, 112, 148, 151, 376, 87], [], [357, 239, 138, 6, 159, 232, 183, 16, 27, 125, 168, 112, 148, 151, 376, 87], [357, 239, 138, 6, 159, 232, 183, 16, 27, 125, 168, 112, 148, 151, 376, 87], [], [], [], [], [], [], [], [395, 186, 4], [], [395, 186, 4], [395, 186, 4], [395, 186, 4], [395, 186, 4], [], [], [357, 232, 372, 395, 186, 116, 4, 151], [], [357, 232, 372, 395, 186, 116, 4, 151], [], [357, 232, 372, 395, 186, 116, 4, 151], [395], [357, 232, 372, 395, 186, 116, 4, 151], [], [357, 232, 372, 395, 186, 116, 4, 151], [357, 232, 372, 395, 186, 116, 4, 151], [357, 395, 186, 4, 151], [357, 232, 372, 395, 186, 116, 4, 151], [], [], [], []]