var clover = new Object();

// JSON: {classes : [{name, id, sl, el,  methods : [{sl, el}, ...]}, ...]}
clover.pageData = {"classes":[{"el":114,"id":3186,"methods":[{"el":56,"sc":2,"sl":53},{"el":63,"sc":2,"sl":62},{"el":70,"sc":2,"sl":68},{"el":77,"sc":2,"sl":75},{"el":91,"sc":2,"sl":80},{"el":105,"sc":2,"sl":93},{"el":111,"sc":2,"sl":107}],"name":"TrailerField","sl":43}]}

// JSON: {test_ID : {"methods": [ID1, ID2, ID3...], "name" : "testXXX() void"}, ...};
clover.testTargets = {"test_105":{"methods":[{"sl":62},{"sl":93}],"name":"Verify that it is possible to parse a SecureMessage generate by interoperability site at https://werkzeug.dcaiti.tu-berlin.de/etsi/ts103097/","pass":true,"statements":[{"sl":95},{"sl":96},{"sl":97},{"sl":98},{"sl":99},{"sl":100}]},"test_13":{"methods":[{"sl":53},{"sl":68},{"sl":75},{"sl":80}],"name":"Generate Signed CAM Message with and verify that all required fields are set and signature verifies.","pass":true,"statements":[{"sl":54},{"sl":55},{"sl":69},{"sl":76},{"sl":82},{"sl":83},{"sl":84},{"sl":85},{"sl":86}]},"test_142":{"methods":[{"sl":68}],"name":"Verify serializeTotalSignedTrailerLength calculates signature trailing fields correctly signature trailer field with uncompressed ecc point","pass":true,"statements":[{"sl":69}]},"test_152":{"methods":[{"sl":53},{"sl":62},{"sl":68},{"sl":75},{"sl":80},{"sl":93}],"name":"Verify that signAndEncryptSecureMessage and verifyAndDecryptSecuredMessage both encrypts and signs properly","pass":true,"statements":[{"sl":54},{"sl":55},{"sl":69},{"sl":76},{"sl":82},{"sl":83},{"sl":84},{"sl":85},{"sl":86},{"sl":95},{"sl":96},{"sl":97},{"sl":98},{"sl":99},{"sl":100}]},"test_176":{"methods":[{"sl":53}],"name":"Verify the constructors, getters and attachSignature","pass":true,"statements":[{"sl":54},{"sl":55}]},"test_184":{"methods":[{"sl":80}],"name":"Verify serialization","pass":true,"statements":[{"sl":82},{"sl":83},{"sl":84},{"sl":85},{"sl":86}]},"test_200":{"methods":[{"sl":107}],"name":"Verify toString","pass":true,"statements":[{"sl":109}]},"test_205":{"methods":[{"sl":68},{"sl":75}],"name":"Verify constructors and getters and setters","pass":true,"statements":[{"sl":69},{"sl":76}]},"test_208":{"methods":[{"sl":62},{"sl":93}],"name":"Verify deserialization","pass":true,"statements":[{"sl":95},{"sl":96},{"sl":97},{"sl":98},{"sl":99},{"sl":100}]},"test_209":{"methods":[{"sl":107}],"name":"Verify toString","pass":true,"statements":[{"sl":109}]},"test_216":{"methods":[{"sl":62},{"sl":68},{"sl":75},{"sl":93}],"name":"Verify signature of reference secure messages from interoperabiltity site at https://werkzeug.dcaiti.tu-berlin.de/etsi/ts103097/","pass":true,"statements":[{"sl":69},{"sl":76},{"sl":95},{"sl":96},{"sl":97},{"sl":98},{"sl":99},{"sl":100}]},"test_284":{"methods":[{"sl":53},{"sl":68},{"sl":75},{"sl":80}],"name":"Generate Authorization Ticket and Signed Secured Message v1 for interoperability testing","pass":true,"statements":[{"sl":54},{"sl":55},{"sl":69},{"sl":76},{"sl":82},{"sl":83},{"sl":84},{"sl":85},{"sl":86}]},"test_289":{"methods":[{"sl":80}],"name":"Verify serialization of RecipientInfo","pass":true,"statements":[{"sl":82},{"sl":83},{"sl":84},{"sl":85},{"sl":86}]},"test_301":{"methods":[{"sl":53},{"sl":68},{"sl":75},{"sl":80}],"name":"Generate Signed DENM Message and verify that all required fields are set and signature verifies.","pass":true,"statements":[{"sl":54},{"sl":55},{"sl":69},{"sl":76},{"sl":82},{"sl":83},{"sl":84},{"sl":85},{"sl":86}]},"test_324":{"methods":[{"sl":68}],"name":"Verify serializeTotalSignedTrailerLength calculates signature trailing fields correctly signature trailer field with compressed_lsb_y_1 ecc point","pass":true,"statements":[{"sl":69}]},"test_341":{"methods":[{"sl":68}],"name":"Verify serializeTotalSignedTrailerLength calculates signature trailing fields correctly signature trailer field with x_coordinate_only ecc point","pass":true,"statements":[{"sl":69}]},"test_397":{"methods":[{"sl":80}],"name":"Verify getEncoded","pass":true,"statements":[{"sl":82},{"sl":83},{"sl":84},{"sl":85},{"sl":86}]},"test_41":{"methods":[{"sl":53},{"sl":68},{"sl":75}],"name":"Verify findSignatureInMessage returns first found signature trailer field","pass":true,"statements":[{"sl":54},{"sl":55},{"sl":69},{"sl":76}]},"test_45":{"methods":[{"sl":68}],"name":"Verify serializeTotalSignedTrailerLength calculates signature trailing fields correctly signature trailer field with compressed_lsb_y_0 ecc point","pass":true,"statements":[{"sl":69}]},"test_49":{"methods":[{"sl":62},{"sl":68},{"sl":75},{"sl":93}],"name":"Verify deserialization of EciesNistP256EncryptedKey","pass":true,"statements":[{"sl":69},{"sl":76},{"sl":95},{"sl":96},{"sl":97},{"sl":98},{"sl":99},{"sl":100}]},"test_7":{"methods":[{"sl":53},{"sl":68},{"sl":75},{"sl":80}],"name":"Generate Signed CAM Unrecognized Certificates Message and verify that all required fields are set and signature verifies.","pass":true,"statements":[{"sl":54},{"sl":55},{"sl":69},{"sl":76},{"sl":82},{"sl":83},{"sl":84},{"sl":85},{"sl":86}]},"test_81":{"methods":[{"sl":53},{"sl":62},{"sl":68},{"sl":75},{"sl":80},{"sl":93}],"name":"Verify SignSecuredMessage using signer info type: certificate_digest_with_ecdsap256 generates a valid signature and that verifySecuredMessage can verify it.","pass":true,"statements":[{"sl":54},{"sl":55},{"sl":69},{"sl":76},{"sl":82},{"sl":83},{"sl":84},{"sl":85},{"sl":86},{"sl":95},{"sl":96},{"sl":97},{"sl":98},{"sl":99},{"sl":100}]},"test_85":{"methods":[{"sl":53},{"sl":62},{"sl":68},{"sl":75},{"sl":80},{"sl":93}],"name":"Verify SignSecuredMessage using signer info type: certificate generates a valid signature and that verifySecuredMessage can verify it.","pass":true,"statements":[{"sl":54},{"sl":55},{"sl":69},{"sl":76},{"sl":82},{"sl":83},{"sl":84},{"sl":85},{"sl":86},{"sl":95},{"sl":96},{"sl":97},{"sl":98},{"sl":99},{"sl":100}]}}

// JSON: { lines : [{tests : [testid1, testid2, testid3, ...]}, ...]};
clover.srcFileLines = [[], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [176, 85, 81, 41, 152, 13, 284, 7, 301], [176, 85, 81, 41, 152, 13, 284, 7, 301], [176, 85, 81, 41, 152, 13, 284, 7, 301], [], [], [], [], [], [], [49, 85, 81, 105, 152, 216, 208], [], [], [], [], [], [49, 85, 142, 81, 41, 324, 152, 13, 205, 284, 216, 341, 7, 301, 45], [49, 85, 142, 81, 41, 324, 152, 13, 205, 284, 216, 341, 7, 301, 45], [], [], [], [], [], [49, 85, 81, 41, 152, 13, 205, 284, 216, 7, 301], [49, 85, 81, 41, 152, 13, 205, 284, 216, 7, 301], [], [], [], [85, 81, 152, 13, 397, 289, 284, 7, 184, 301], [], [85, 81, 152, 13, 397, 289, 284, 7, 184, 301], [85, 81, 152, 13, 397, 289, 284, 7, 184, 301], [85, 81, 152, 13, 397, 289, 284, 7, 184, 301], [85, 81, 152, 13, 397, 289, 284, 7, 184, 301], [85, 81, 152, 13, 397, 289, 284, 7, 184, 301], [], [], [], [], [], [], [49, 85, 81, 105, 152, 216, 208], [], [49, 85, 81, 105, 152, 216, 208], [49, 85, 81, 105, 152, 216, 208], [49, 85, 81, 105, 152, 216, 208], [49, 85, 81, 105, 152, 216, 208], [49, 85, 81, 105, 152, 216, 208], [49, 85, 81, 105, 152, 216, 208], [], [], [], [], [], [], [209, 200], [], [209, 200], [], [], [], [], []]
