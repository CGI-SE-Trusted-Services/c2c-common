var clover = new Object();

// JSON: {classes : [{name, id, sl, el,  methods : [{sl, el}, ...]}, ...]}
clover.pageData = {"classes":[{"el":221,"id":3129,"methods":[{"el":77,"sc":2,"sl":72},{"el":99,"sc":2,"sl":93},{"el":110,"sc":2,"sl":107},{"el":118,"sc":2,"sl":117},{"el":126,"sc":2,"sl":124},{"el":133,"sc":2,"sl":131},{"el":142,"sc":2,"sl":140},{"el":150,"sc":2,"sl":148},{"el":159,"sc":2,"sl":157},{"el":171,"sc":2,"sl":166},{"el":183,"sc":2,"sl":173},{"el":198,"sc":2,"sl":185},{"el":206,"sc":2,"sl":200},{"el":219,"sc":2,"sl":214}],"name":"SecuredMessage","sl":49}]}

// JSON: {test_ID : {"methods": [ID1, ID2, ID3...], "name" : "testXXX() void"}, ...};
clover.testTargets = {"test_123":{"methods":[{"sl":72},{"sl":124},{"sl":131},{"sl":140},{"sl":148},{"sl":157},{"sl":166},{"sl":173},{"sl":214}],"name":"Generate Signed CAM Message with and verify that all required fields are set and signature verifies.","pass":true,"statements":[{"sl":73},{"sl":74},{"sl":75},{"sl":76},{"sl":125},{"sl":132},{"sl":141},{"sl":149},{"sl":158},{"sl":167},{"sl":170},{"sl":175},{"sl":176},{"sl":178},{"sl":179},{"sl":180},{"sl":181},{"sl":215},{"sl":216},{"sl":217},{"sl":218}]},"test_14":{"methods":[{"sl":72},{"sl":107},{"sl":124},{"sl":131},{"sl":140},{"sl":148},{"sl":157},{"sl":166},{"sl":173},{"sl":185},{"sl":214}],"name":"Verify SignSecuredMessage using signer info type: certificate generates a valid signature and that verifySecuredMessage can verify it.","pass":true,"statements":[{"sl":73},{"sl":74},{"sl":75},{"sl":76},{"sl":108},{"sl":109},{"sl":125},{"sl":132},{"sl":141},{"sl":149},{"sl":158},{"sl":167},{"sl":170},{"sl":175},{"sl":176},{"sl":178},{"sl":179},{"sl":180},{"sl":181},{"sl":188},{"sl":189},{"sl":191},{"sl":192},{"sl":193},{"sl":194},{"sl":215},{"sl":216},{"sl":217},{"sl":218}]},"test_151":{"methods":[{"sl":72},{"sl":140}],"name":"Verify that findHeader finds the correct header in a SecureMessage","pass":true,"statements":[{"sl":73},{"sl":74},{"sl":75},{"sl":76},{"sl":141}]},"test_162":{"methods":[{"sl":72},{"sl":124},{"sl":131},{"sl":140},{"sl":148},{"sl":157},{"sl":166},{"sl":173},{"sl":214}],"name":"Generate Authorization Ticket and Signed Secured Message v1 for interoperability testing","pass":true,"statements":[{"sl":73},{"sl":74},{"sl":75},{"sl":76},{"sl":125},{"sl":132},{"sl":141},{"sl":149},{"sl":158},{"sl":167},{"sl":170},{"sl":175},{"sl":176},{"sl":178},{"sl":179},{"sl":180},{"sl":181},{"sl":215},{"sl":216},{"sl":217},{"sl":218}]},"test_168":{"methods":[{"sl":93},{"sl":117},{"sl":157}],"name":"Verify findSignatureInMessage throws exception if no signature element was found.","pass":true,"statements":[{"sl":94},{"sl":95},{"sl":96},{"sl":97},{"sl":98},{"sl":158}]},"test_171":{"methods":[{"sl":72},{"sl":140}],"name":"Verify that addHeader adds the header value in correct order","pass":true,"statements":[{"sl":73},{"sl":74},{"sl":75},{"sl":76},{"sl":141}]},"test_20":{"methods":[{"sl":72},{"sl":124},{"sl":131},{"sl":140},{"sl":148},{"sl":157},{"sl":166},{"sl":173},{"sl":214}],"name":"Generate Signed CAM Unrecognized Certificates Message and verify that all required fields are set and signature verifies.","pass":true,"statements":[{"sl":73},{"sl":74},{"sl":75},{"sl":76},{"sl":125},{"sl":132},{"sl":141},{"sl":149},{"sl":158},{"sl":167},{"sl":170},{"sl":175},{"sl":176},{"sl":178},{"sl":179},{"sl":180},{"sl":181},{"sl":215},{"sl":216},{"sl":217},{"sl":218}]},"test_203":{"methods":[{"sl":72},{"sl":124},{"sl":131},{"sl":140},{"sl":148},{"sl":157},{"sl":166},{"sl":173},{"sl":214}],"name":"Generate Signed DENM Message and verify that all required fields are set and signature verifies.","pass":true,"statements":[{"sl":73},{"sl":74},{"sl":75},{"sl":76},{"sl":125},{"sl":132},{"sl":141},{"sl":149},{"sl":158},{"sl":167},{"sl":170},{"sl":175},{"sl":176},{"sl":178},{"sl":179},{"sl":180},{"sl":181},{"sl":215},{"sl":216},{"sl":217},{"sl":218}]},"test_26":{"methods":[{"sl":173}],"name":"Verify serialization","pass":true,"statements":[{"sl":175},{"sl":176},{"sl":178},{"sl":179},{"sl":180},{"sl":181}]},"test_265":{"methods":[{"sl":72},{"sl":107},{"sl":124},{"sl":131},{"sl":140},{"sl":148},{"sl":157},{"sl":166},{"sl":173},{"sl":185},{"sl":214}],"name":"Verify that signAndEncryptSecureMessage and verifyAndDecryptSecuredMessage both encrypts and signs properly","pass":true,"statements":[{"sl":73},{"sl":74},{"sl":75},{"sl":76},{"sl":108},{"sl":109},{"sl":125},{"sl":132},{"sl":141},{"sl":149},{"sl":158},{"sl":167},{"sl":170},{"sl":175},{"sl":176},{"sl":178},{"sl":179},{"sl":180},{"sl":181},{"sl":188},{"sl":189},{"sl":191},{"sl":192},{"sl":193},{"sl":194},{"sl":196},{"sl":215},{"sl":216},{"sl":217},{"sl":218}]},"test_283":{"methods":[{"sl":200}],"name":"Verify toString","pass":true,"statements":[{"sl":202}]},"test_289":{"methods":[{"sl":72},{"sl":107},{"sl":124},{"sl":131},{"sl":140},{"sl":148},{"sl":157},{"sl":166},{"sl":173},{"sl":185},{"sl":214}],"name":"Verify SignSecuredMessage using signer info type: certificate_digest_with_ecdsap256 generates a valid signature and that verifySecuredMessage can verify it.","pass":true,"statements":[{"sl":73},{"sl":74},{"sl":75},{"sl":76},{"sl":108},{"sl":109},{"sl":125},{"sl":132},{"sl":141},{"sl":149},{"sl":158},{"sl":167},{"sl":170},{"sl":175},{"sl":176},{"sl":178},{"sl":179},{"sl":180},{"sl":181},{"sl":188},{"sl":189},{"sl":191},{"sl":192},{"sl":193},{"sl":194},{"sl":215},{"sl":216},{"sl":217},{"sl":218}]},"test_350":{"methods":[{"sl":107},{"sl":124},{"sl":131},{"sl":140},{"sl":148},{"sl":157},{"sl":185}],"name":"Verify signature of reference secure messages from interoperabiltity site at https://werkzeug.dcaiti.tu-berlin.de/etsi/ts103097/","pass":true,"statements":[{"sl":108},{"sl":109},{"sl":125},{"sl":132},{"sl":141},{"sl":149},{"sl":158},{"sl":188},{"sl":189},{"sl":191},{"sl":192},{"sl":193},{"sl":194}]},"test_366":{"methods":[{"sl":173},{"sl":214}],"name":"Verify getEncoded","pass":true,"statements":[{"sl":175},{"sl":176},{"sl":178},{"sl":179},{"sl":180},{"sl":181},{"sl":215},{"sl":216},{"sl":217},{"sl":218}]},"test_376":{"methods":[{"sl":124},{"sl":131},{"sl":140},{"sl":148},{"sl":157},{"sl":166}],"name":"Verify the constructors, getters and attachSignature","pass":true,"statements":[{"sl":125},{"sl":132},{"sl":141},{"sl":149},{"sl":158},{"sl":167},{"sl":170}]},"test_387":{"methods":[{"sl":72},{"sl":107},{"sl":140},{"sl":148},{"sl":173},{"sl":185},{"sl":214}],"name":"verify that encryptSecureMessage and decryptSecureMessage encrypts and decrypts correctly","pass":true,"statements":[{"sl":73},{"sl":74},{"sl":75},{"sl":76},{"sl":108},{"sl":109},{"sl":141},{"sl":149},{"sl":175},{"sl":176},{"sl":178},{"sl":179},{"sl":180},{"sl":188},{"sl":189},{"sl":191},{"sl":192},{"sl":193},{"sl":196},{"sl":215},{"sl":216},{"sl":217},{"sl":218}]},"test_56":{"methods":[{"sl":107},{"sl":124},{"sl":131},{"sl":140},{"sl":148},{"sl":157},{"sl":185}],"name":"Verify that it is possible to parse a SecureMessage generate by interoperability site at https://werkzeug.dcaiti.tu-berlin.de/etsi/ts103097/","pass":true,"statements":[{"sl":108},{"sl":109},{"sl":125},{"sl":132},{"sl":141},{"sl":149},{"sl":158},{"sl":188},{"sl":189},{"sl":191},{"sl":192},{"sl":193},{"sl":194}]},"test_63":{"methods":[{"sl":117},{"sl":124},{"sl":131},{"sl":140},{"sl":148},{"sl":157},{"sl":185}],"name":"Verify deserialization","pass":true,"statements":[{"sl":125},{"sl":132},{"sl":141},{"sl":149},{"sl":158},{"sl":188},{"sl":189},{"sl":191},{"sl":192},{"sl":193},{"sl":194}]},"test_71":{"methods":[{"sl":72},{"sl":124},{"sl":131},{"sl":140},{"sl":148},{"sl":157}],"name":"Verify that serializeDataToBeSignedInSecuredMessage serializes according to signature verification it ETSI specifification","pass":true,"statements":[{"sl":73},{"sl":74},{"sl":75},{"sl":76},{"sl":125},{"sl":132},{"sl":141},{"sl":149},{"sl":158}]},"test_81":{"methods":[{"sl":93},{"sl":157}],"name":"Verify findSignatureInMessage returns first found signature trailer field","pass":true,"statements":[{"sl":94},{"sl":95},{"sl":96},{"sl":97},{"sl":98},{"sl":158}]}}

// JSON: { lines : [{tests : [testid1, testid2, testid3, ...]}, ...]};
clover.srcFileLines = [[], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [123, 289, 265, 171, 20, 14, 151, 203, 387, 162, 71], [123, 289, 265, 171, 20, 14, 151, 203, 387, 162, 71], [123, 289, 265, 171, 20, 14, 151, 203, 387, 162, 71], [123, 289, 265, 171, 20, 14, 151, 203, 387, 162, 71], [123, 289, 265, 171, 20, 14, 151, 203, 387, 162, 71], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [168, 81], [168, 81], [168, 81], [168, 81], [168, 81], [168, 81], [], [], [], [], [], [], [], [], [289, 265, 14, 56, 387, 350], [289, 265, 14, 56, 387, 350], [289, 265, 14, 56, 387, 350], [], [], [], [], [], [], [], [168, 63], [], [], [], [], [], [], [123, 289, 265, 20, 14, 56, 203, 376, 350, 162, 63, 71], [123, 289, 265, 20, 14, 56, 203, 376, 350, 162, 63, 71], [], [], [], [], [], [123, 289, 265, 20, 14, 56, 203, 376, 350, 162, 63, 71], [123, 289, 265, 20, 14, 56, 203, 376, 350, 162, 63, 71], [], [], [], [], [], [], [], [123, 289, 265, 171, 20, 14, 56, 151, 203, 387, 376, 350, 162, 63, 71], [123, 289, 265, 171, 20, 14, 56, 151, 203, 387, 376, 350, 162, 63, 71], [], [], [], [], [], [], [123, 289, 265, 20, 14, 56, 203, 387, 376, 350, 162, 63, 71], [123, 289, 265, 20, 14, 56, 203, 387, 376, 350, 162, 63, 71], [], [], [], [], [], [], [], [123, 168, 289, 265, 81, 20, 14, 56, 203, 376, 350, 162, 63, 71], [123, 168, 289, 265, 81, 20, 14, 56, 203, 376, 350, 162, 63, 71], [], [], [], [], [], [], [], [123, 289, 265, 20, 14, 203, 376, 162], [123, 289, 265, 20, 14, 203, 376, 162], [], [], [123, 289, 265, 20, 14, 203, 376, 162], [], [], [123, 289, 265, 366, 20, 14, 203, 387, 162, 26], [], [123, 289, 265, 366, 20, 14, 203, 387, 162, 26], [123, 289, 265, 366, 20, 14, 203, 387, 162, 26], [], [123, 289, 265, 366, 20, 14, 203, 387, 162, 26], [123, 289, 265, 366, 20, 14, 203, 387, 162, 26], [123, 289, 265, 366, 20, 14, 203, 387, 162, 26], [123, 289, 265, 366, 20, 14, 203, 162, 26], [], [], [], [289, 265, 14, 56, 387, 350, 63], [], [], [289, 265, 14, 56, 387, 350, 63], [289, 265, 14, 56, 387, 350, 63], [], [289, 265, 14, 56, 387, 350, 63], [289, 265, 14, 56, 387, 350, 63], [289, 265, 14, 56, 387, 350, 63], [289, 265, 14, 56, 350, 63], [], [265, 387], [], [], [], [283], [], [283], [], [], [], [], [], [], [], [], [], [], [], [123, 289, 265, 366, 20, 14, 203, 387, 162], [123, 289, 265, 366, 20, 14, 203, 387, 162], [123, 289, 265, 366, 20, 14, 203, 387, 162], [123, 289, 265, 366, 20, 14, 203, 387, 162], [123, 289, 265, 366, 20, 14, 203, 387, 162], [], [], []]
