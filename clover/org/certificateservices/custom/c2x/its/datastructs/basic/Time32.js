var clover = new Object();

// JSON: {classes : [{name, id, sl, el,  methods : [{sl, el}, ...]}, ...]}
clover.pageData = {"classes":[{"el":136,"id":1794,"methods":[{"el":56,"sc":2,"sl":51},{"el":65,"sc":2,"sl":63},{"el":74,"sc":2,"sl":71},{"el":85,"sc":2,"sl":82},{"el":93,"sc":2,"sl":91},{"el":99,"sc":2,"sl":96},{"el":106,"sc":2,"sl":101},{"el":111,"sc":2,"sl":108},{"el":119,"sc":2,"sl":113},{"el":133,"sc":2,"sl":121}],"name":"Time32","sl":38}]}

// JSON: {test_ID : {"methods": [ID1, ID2, ID3...], "name" : "testXXX() void"}, ...};
clover.testTargets = {"test_102":{"methods":[{"sl":82},{"sl":108}],"name":"Verify toString","pass":true,"statements":[{"sl":83},{"sl":84},{"sl":110}]},"test_103":{"methods":[{"sl":63},{"sl":96}],"name":"Verify that serializeDataToBeSignedInSecuredMessage serializes according to signature verification it ETSI specifification","pass":true,"statements":[{"sl":64},{"sl":98}]},"test_105":{"methods":[{"sl":71},{"sl":101}],"name":"Verify that it is possible to parse a SecureMessage generate by interoperability site at https://werkzeug.dcaiti.tu-berlin.de/etsi/ts103097/","pass":true,"statements":[{"sl":103},{"sl":104},{"sl":105}]},"test_114":{"methods":[{"sl":82},{"sl":108}],"name":"Verify toString","pass":true,"statements":[{"sl":83},{"sl":84},{"sl":110}]},"test_115":{"methods":[{"sl":71},{"sl":82},{"sl":101}],"name":"Verify deserialization","pass":true,"statements":[{"sl":83},{"sl":84},{"sl":103},{"sl":104},{"sl":105}]},"test_116":{"methods":[{"sl":51},{"sl":96}],"name":"Generate Enrollment Credential v1 for interoperability testing","pass":true,"statements":[{"sl":52},{"sl":53},{"sl":54},{"sl":98}]},"test_120":{"methods":[{"sl":51},{"sl":82},{"sl":96}],"name":"Generate Enrollment Credential with a certificate as signer info","pass":true,"statements":[{"sl":52},{"sl":53},{"sl":54},{"sl":83},{"sl":84},{"sl":98}]},"test_123":{"methods":[{"sl":71},{"sl":101}],"name":"Verify getVerificationKey","pass":true,"statements":[{"sl":103},{"sl":104},{"sl":105}]},"test_13":{"methods":[{"sl":96}],"name":"Generate Signed CAM Message with and verify that all required fields are set and signature verifies.","pass":true,"statements":[{"sl":98}]},"test_135":{"methods":[{"sl":51},{"sl":82},{"sl":96}],"name":"Generate Authorization Ticket with a digest as signer info","pass":true,"statements":[{"sl":52},{"sl":53},{"sl":54},{"sl":83},{"sl":84},{"sl":98}]},"test_152":{"methods":[{"sl":71},{"sl":96},{"sl":101}],"name":"Verify that signAndEncryptSecureMessage and verifyAndDecryptSecuredMessage both encrypts and signs properly","pass":true,"statements":[{"sl":98},{"sl":103},{"sl":104},{"sl":105}]},"test_154":{"methods":[{"sl":82},{"sl":108}],"name":"Verify toString","pass":true,"statements":[{"sl":83},{"sl":84},{"sl":110}]},"test_156":{"methods":[{"sl":63},{"sl":96}],"name":"Verify serialization","pass":true,"statements":[{"sl":64},{"sl":98}]},"test_158":{"methods":[{"sl":71},{"sl":96},{"sl":101}],"name":"Verify that findRecipientInfo find correct RecipientInfo","pass":true,"statements":[{"sl":98},{"sl":103},{"sl":104},{"sl":105}]},"test_166":{"methods":[{"sl":71},{"sl":96},{"sl":101}],"name":"Verify that serializeCertWithoutSignature encodes the certificate without the signature correcly","pass":true,"statements":[{"sl":98},{"sl":103},{"sl":104},{"sl":105}]},"test_168":{"methods":[{"sl":63},{"sl":82}],"name":"Make sure asDate converts the date correctly","pass":true,"statements":[{"sl":64},{"sl":83},{"sl":84}]},"test_170":{"methods":[{"sl":96}],"name":"Verify serialization","pass":true,"statements":[{"sl":98}]},"test_173":{"methods":[{"sl":96}],"name":"Verify serialization","pass":true,"statements":[{"sl":98}]},"test_175":{"methods":[{"sl":51}],"name":"Verify that findHeader finds the correct header in a SecureMessage","pass":true,"statements":[{"sl":52},{"sl":53},{"sl":54}]},"test_18":{"methods":[{"sl":51},{"sl":82},{"sl":108}],"name":"Verify toString","pass":true,"statements":[{"sl":52},{"sl":53},{"sl":54},{"sl":83},{"sl":84},{"sl":110}]},"test_185":{"methods":[{"sl":51},{"sl":82},{"sl":96}],"name":"Generate RootCA without Encryption Key and Geographic region and verify that all other attributes are set.","pass":true,"statements":[{"sl":52},{"sl":53},{"sl":54},{"sl":83},{"sl":84},{"sl":98}]},"test_201":{"methods":[{"sl":82}],"name":"Verify the constructors and getters","pass":true,"statements":[{"sl":83},{"sl":84}]},"test_202":{"methods":[{"sl":71},{"sl":101}],"name":"Verify deserialization","pass":true,"statements":[{"sl":103},{"sl":104},{"sl":105}]},"test_216":{"methods":[{"sl":71},{"sl":96},{"sl":101}],"name":"Verify signature of reference secure messages from interoperabiltity site at https://werkzeug.dcaiti.tu-berlin.de/etsi/ts103097/","pass":true,"statements":[{"sl":98},{"sl":103},{"sl":104},{"sl":105}]},"test_221":{"methods":[{"sl":71},{"sl":101}],"name":"Verify deserialization","pass":true,"statements":[{"sl":103},{"sl":104},{"sl":105}]},"test_236":{"methods":[{"sl":51}],"name":"Verify that addHeader adds the header value in correct order","pass":true,"statements":[{"sl":52},{"sl":53},{"sl":54}]},"test_244":{"methods":[{"sl":51},{"sl":82},{"sl":96}],"name":"Generate Enrollment Credential with a certificate chain as signer info","pass":true,"statements":[{"sl":52},{"sl":53},{"sl":54},{"sl":83},{"sl":84},{"sl":98}]},"test_249":{"methods":[{"sl":51},{"sl":91}],"name":"Verify the constructors and asElapsedTime","pass":true,"statements":[{"sl":52},{"sl":53},{"sl":54},{"sl":92}]},"test_271":{"methods":[{"sl":71},{"sl":101}],"name":"Verify getEncryptionKey","pass":true,"statements":[{"sl":103},{"sl":104},{"sl":105}]},"test_274":{"methods":[{"sl":51},{"sl":82},{"sl":96}],"name":"Generate Authorization Credential with a certificate chain as signer info","pass":true,"statements":[{"sl":52},{"sl":53},{"sl":54},{"sl":83},{"sl":84},{"sl":98}]},"test_275":{"methods":[{"sl":96}],"name":"Verify getEncoded","pass":true,"statements":[{"sl":98}]},"test_284":{"methods":[{"sl":51},{"sl":96}],"name":"Generate Authorization Ticket and Signed Secured Message v1 for interoperability testing","pass":true,"statements":[{"sl":52},{"sl":53},{"sl":54},{"sl":98}]},"test_301":{"methods":[{"sl":96}],"name":"Generate Signed DENM Message and verify that all required fields are set and signature verifies.","pass":true,"statements":[{"sl":98}]},"test_313":{"methods":[{"sl":51},{"sl":113},{"sl":121}],"name":"Verify hashCode and equals","pass":true,"statements":[{"sl":52},{"sl":53},{"sl":54},{"sl":115},{"sl":116},{"sl":117},{"sl":118},{"sl":123},{"sl":125},{"sl":127},{"sl":129},{"sl":130},{"sl":131},{"sl":132}]},"test_314":{"methods":[{"sl":51},{"sl":82},{"sl":96}],"name":"Generate Enrollment Authority and verify that it is signed by the Root CA","pass":true,"statements":[{"sl":52},{"sl":53},{"sl":54},{"sl":83},{"sl":84},{"sl":98}]},"test_322":{"methods":[{"sl":71},{"sl":96},{"sl":101}],"name":"Verify deserialization and serialization of reference ETSI Certificates works","pass":true,"statements":[{"sl":98},{"sl":103},{"sl":104},{"sl":105}]},"test_34":{"methods":[{"sl":71},{"sl":96},{"sl":101}],"name":"Test to verifyCertificate","pass":true,"statements":[{"sl":98},{"sl":103},{"sl":104},{"sl":105}]},"test_354":{"methods":[{"sl":51},{"sl":113},{"sl":121}],"name":"Verify hashCode and equals","pass":true,"statements":[{"sl":52},{"sl":53},{"sl":54},{"sl":115},{"sl":116},{"sl":117},{"sl":118},{"sl":123},{"sl":125},{"sl":126},{"sl":127},{"sl":129},{"sl":130},{"sl":132}]},"test_364":{"methods":[{"sl":51},{"sl":82},{"sl":96}],"name":"Generate RootCA with Encryption Key and Geographic region and verify that all attributes are set.","pass":true,"statements":[{"sl":52},{"sl":53},{"sl":54},{"sl":83},{"sl":84},{"sl":98}]},"test_374":{"methods":[{"sl":71},{"sl":82},{"sl":101}],"name":"Verify deserialization","pass":true,"statements":[{"sl":83},{"sl":84},{"sl":103},{"sl":104},{"sl":105}]},"test_39":{"methods":[{"sl":96}],"name":"Verify serialization","pass":true,"statements":[{"sl":98}]},"test_403":{"methods":[{"sl":51},{"sl":96}],"name":"Generate Authorization CA v1 for interoperability testing","pass":true,"statements":[{"sl":52},{"sl":53},{"sl":54},{"sl":98}]},"test_405":{"methods":[{"sl":51},{"sl":82},{"sl":96}],"name":"Generate Enrollment Credential with a digest as signer info","pass":true,"statements":[{"sl":52},{"sl":53},{"sl":54},{"sl":83},{"sl":84},{"sl":98}]},"test_406":{"methods":[{"sl":51},{"sl":82},{"sl":96}],"name":"Generate Authorization Authority and verify that it is signed by the Root CA","pass":true,"statements":[{"sl":52},{"sl":53},{"sl":54},{"sl":83},{"sl":84},{"sl":98}]},"test_64":{"methods":[{"sl":96}],"name":"verify that encryptSecureMessage and decryptSecureMessage encrypts and decrypts correctly","pass":true,"statements":[{"sl":98}]},"test_7":{"methods":[{"sl":96}],"name":"Generate Signed CAM Unrecognized Certificates Message and verify that all required fields are set and signature verifies.","pass":true,"statements":[{"sl":98}]},"test_73":{"methods":[{"sl":51},{"sl":82},{"sl":96}],"name":"Generate Authorization Ticket with a certificate as signer info","pass":true,"statements":[{"sl":52},{"sl":53},{"sl":54},{"sl":83},{"sl":84},{"sl":98}]},"test_75":{"methods":[{"sl":71},{"sl":101}],"name":"Verify deserialization","pass":true,"statements":[{"sl":103},{"sl":104},{"sl":105}]},"test_81":{"methods":[{"sl":71},{"sl":96},{"sl":101}],"name":"Verify SignSecuredMessage using signer info type: certificate_digest_with_ecdsap256 generates a valid signature and that verifySecuredMessage can verify it.","pass":true,"statements":[{"sl":98},{"sl":103},{"sl":104},{"sl":105}]},"test_85":{"methods":[{"sl":71},{"sl":96},{"sl":101}],"name":"Verify SignSecuredMessage using signer info type: certificate generates a valid signature and that verifySecuredMessage can verify it.","pass":true,"statements":[{"sl":98},{"sl":103},{"sl":104},{"sl":105}]},"test_88":{"methods":[{"sl":96}],"name":"Verify serialization","pass":true,"statements":[{"sl":98}]}}

// JSON: { lines : [{tests : [testid1, testid2, testid3, ...]}, ...]};
clover.srcFileLines = [[], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [313, 120, 73, 249, 364, 284, 18, 405, 403, 274, 314, 236, 406, 185, 354, 244, 116, 135, 175], [313, 120, 73, 249, 364, 284, 18, 405, 403, 274, 314, 236, 406, 185, 354, 244, 116, 135, 175], [313, 120, 73, 249, 364, 284, 18, 405, 403, 274, 314, 236, 406, 185, 354, 244, 116, 135, 175], [313, 120, 73, 249, 364, 284, 18, 405, 403, 274, 314, 236, 406, 185, 354, 244, 116, 135, 175], [], [], [], [], [], [], [], [], [103, 156, 168], [103, 156, 168], [], [], [], [], [], [], [158, 322, 202, 271, 34, 115, 374, 85, 81, 105, 123, 166, 152, 75, 216, 221], [], [], [], [], [], [], [], [], [], [], [154, 201, 120, 73, 364, 18, 405, 115, 374, 274, 314, 406, 114, 185, 244, 168, 135, 102], [154, 201, 120, 73, 364, 18, 405, 115, 374, 274, 314, 406, 114, 185, 244, 168, 135, 102], [154, 201, 120, 73, 364, 18, 405, 115, 374, 274, 314, 406, 114, 185, 244, 168, 135, 102], [], [], [], [], [], [], [249], [249], [], [], [], [39, 120, 158, 73, 173, 88, 13, 364, 284, 103, 275, 156, 322, 405, 403, 7, 34, 274, 85, 314, 81, 406, 170, 185, 244, 166, 152, 116, 216, 135, 301, 64], [], [39, 120, 158, 73, 173, 88, 13, 364, 284, 103, 275, 156, 322, 405, 403, 7, 34, 274, 85, 314, 81, 406, 170, 185, 244, 166, 152, 116, 216, 135, 301, 64], [], [], [158, 322, 202, 271, 34, 115, 374, 85, 81, 105, 123, 166, 152, 75, 216, 221], [], [158, 322, 202, 271, 34, 115, 374, 85, 81, 105, 123, 166, 152, 75, 216, 221], [158, 322, 202, 271, 34, 115, 374, 85, 81, 105, 123, 166, 152, 75, 216, 221], [158, 322, 202, 271, 34, 115, 374, 85, 81, 105, 123, 166, 152, 75, 216, 221], [], [], [154, 18, 114, 102], [], [154, 18, 114, 102], [], [], [313, 354], [], [313, 354], [313, 354], [313, 354], [313, 354], [], [], [313, 354], [], [313, 354], [], [313, 354], [354], [313, 354], [], [313, 354], [313, 354], [313], [313, 354], [], [], [], []]
