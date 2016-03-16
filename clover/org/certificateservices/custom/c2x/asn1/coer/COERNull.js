var clover = new Object();

// JSON: {classes : [{name, id, sl, el,  methods : [{sl, el}, ...]}, ...]}
clover.pageData = {"classes":[{"el":68,"id":593,"methods":[{"el":35,"sc":2,"sl":34},{"el":40,"sc":2,"sl":37},{"el":51,"sc":2,"sl":42},{"el":57,"sc":2,"sl":54},{"el":62,"sc":2,"sl":59},{"el":67,"sc":2,"sl":64}],"name":"COERNull","sl":26}]}

// JSON: {test_ID : {"methods": [ID1, ID2, ID3...], "name" : "testXXX() void"}, ...};
clover.testTargets = {"test_0":{"methods":[{"sl":34},{"sl":54}],"name":"Verify that Ieee1609Dot2 Authorization Cert is generated correctly of explicit certificate for alg: ecdsaNistP256","pass":true,"statements":[]},"test_128":{"methods":[{"sl":34},{"sl":54}],"name":"Verify that getSignerIdentifier returns first signing certificate from a chain for type SIGNER_CERTIFICATE","pass":true,"statements":[]},"test_129":{"methods":[{"sl":34},{"sl":54},{"sl":59}],"name":"Verify that SspRange is correctly encoded for type all","pass":true,"statements":[]},"test_136":{"methods":[{"sl":34}],"name":"Verify that Ieee1609dot2Peer2PeerPDUContent is correctly encoded for type caCerts","pass":true,"statements":[]},"test_149":{"methods":[{"sl":34},{"sl":42},{"sl":54},{"sl":59}],"name":"Verify that CertificateId is correctly encoded for type none","pass":true,"statements":[{"sl":44},{"sl":46},{"sl":48},{"sl":50}]},"test_153":{"methods":[{"sl":34},{"sl":42},{"sl":54},{"sl":59}],"name":"Verify that constructor and getters are correct and it is correctly encoded","pass":true,"statements":[{"sl":44},{"sl":46},{"sl":48},{"sl":50}]},"test_16":{"methods":[{"sl":34},{"sl":42},{"sl":54},{"sl":59}],"name":"Verify that constructor and getters are correct and it is correctly encoded for implicit certificates","pass":true,"statements":[{"sl":44},{"sl":46},{"sl":48},{"sl":50}]},"test_163":{"methods":[{"sl":34},{"sl":54}],"name":"Verify that Ieee1609Dot2 Long term CA is generated correctly of implicit certificate for alg: ecdsaBrainpoolP256r1","pass":true,"statements":[]},"test_168":{"methods":[{"sl":34}],"name":"Verify toString","pass":true,"statements":[]},"test_172":{"methods":[{"sl":34}],"name":"Verify toString","pass":true,"statements":[]},"test_185":{"methods":[{"sl":34}],"name":"Verify toString","pass":true,"statements":[]},"test_199":{"methods":[{"sl":34}],"name":"Verify that IllegalArgumentException is thrown if none of required premissions doesn't exists","pass":true,"statements":[]},"test_210":{"methods":[{"sl":34}],"name":"Verify that CertificateId is correctly encoded for type binaryId","pass":true,"statements":[]},"test_226":{"methods":[{"sl":34},{"sl":54}],"name":"Verify that Ieee1609Dot2 Enrollment Cert is generated correctly for implicit CA certificate for alg: ecdsaBrainpoolP256r1","pass":true,"statements":[]},"test_23":{"methods":[{"sl":34},{"sl":54},{"sl":59}],"name":"Verify that COERNull with value #value returns #encoded encoded and encoded #encoded generates a #value value","pass":true,"statements":[]},"test_239":{"methods":[{"sl":34},{"sl":54}],"name":"Verify that encryption works with certificate public encryption key for alg: ecdsaBrainpoolP256r1","pass":true,"statements":[]},"test_246":{"methods":[{"sl":34}],"name":"Verify toString","pass":true,"statements":[]},"test_248":{"methods":[{"sl":34},{"sl":54}],"name":"Verify that getSignedDataStore returns a populate map of all certificate if SignerIdentifier is certificate","pass":true,"statements":[]},"test_249":{"methods":[{"sl":34}],"name":"Verify that constructor contains Ieee1609Dot2Data  if content  fullfill requirements","pass":true,"statements":[]},"test_257":{"methods":[{"sl":34}],"name":"Verify that IllegalArgumentException is thrown if both data and exthash is null","pass":true,"statements":[]},"test_261":{"methods":[{"sl":34},{"sl":54}],"name":"Verify that return first certificates public key of complete chain consists of explicit certificates","pass":true,"statements":[]},"test_278":{"methods":[{"sl":34},{"sl":54}],"name":"Verify that Ieee1609Dot2 Enrollment Cert is generated correctly for implicit CA certificate for alg: ecdsaBrainpoolP256r1","pass":true,"statements":[]},"test_312":{"methods":[{"sl":34},{"sl":54}],"name":"Verify that findFromStores finds certificate from stores","pass":true,"statements":[]},"test_324":{"methods":[{"sl":34},{"sl":54}],"name":"Verify that getSignerId returns the included HashedId8 if type is digest","pass":true,"statements":[]},"test_325":{"methods":[{"sl":34}],"name":"Verify toString","pass":true,"statements":[]},"test_326":{"methods":[{"sl":34}],"name":"Verify toString","pass":true,"statements":[]},"test_35":{"methods":[{"sl":34},{"sl":54}],"name":"Verify that signAndEncryptData and decryptAndVerifySignedData generates encrypted and signed data structures for alg: ecdsaNistP256","pass":true,"statements":[]},"test_354":{"methods":[{"sl":34},{"sl":54}],"name":"Verify that Ieee1609Dot2 Root CA is generated correctly for explicit certificate (only type supported) for alg: ecdsaBrainpoolP256r1","pass":true,"statements":[]},"test_360":{"methods":[{"sl":34},{"sl":54}],"name":"Verify that Ieee1609Dot2 Enrollment Cert is generated correctly for implicit CA certificate for alg: ecdsaNistP256","pass":true,"statements":[]},"test_373":{"methods":[{"sl":34},{"sl":42},{"sl":54},{"sl":59}],"name":"Verify that SubjectPermissions is correctly encoded for type all","pass":true,"statements":[{"sl":44},{"sl":46},{"sl":48},{"sl":50}]},"test_385":{"methods":[{"sl":34},{"sl":54}],"name":"Verify that signed Ieee1609Dot2Data with signed data is generated correctly for alg: ecdsaBrainpoolP256r1","pass":true,"statements":[]},"test_387":{"methods":[{"sl":34},{"sl":42},{"sl":59}],"name":"Verify that SequenceOfPsidSspRange is initialized properly","pass":true,"statements":[{"sl":44},{"sl":46},{"sl":48},{"sl":50}]},"test_406":{"methods":[{"sl":34},{"sl":54}],"name":"Verify that signed Ieee1609Dot2Data with signed data is generated correctly for alg: ecdsaNistP256","pass":true,"statements":[]},"test_413":{"methods":[{"sl":34}],"name":"Verify that fullfillsRequirements verifies all required fields","pass":true,"statements":[]},"test_417":{"methods":[{"sl":34}],"name":"Verify that CaCertP2pPDU is initialized properly","pass":true,"statements":[]},"test_422":{"methods":[{"sl":34},{"sl":42},{"sl":54},{"sl":59}],"name":"Verify that encode and decode to byte array is correct","pass":true,"statements":[{"sl":44},{"sl":46},{"sl":48},{"sl":50}]},"test_43":{"methods":[{"sl":34}],"name":"Verify that CertificateId is correctly encoded for type name","pass":true,"statements":[]},"test_437":{"methods":[{"sl":34},{"sl":42},{"sl":54},{"sl":59}],"name":"Verify that constructor and getters are correct and it is correctly encoded for explicit certificates","pass":true,"statements":[{"sl":44},{"sl":46},{"sl":48},{"sl":50}]},"test_455":{"methods":[{"sl":34},{"sl":54}],"name":"Verify that Ieee1609Dot2 Enrollment Cert is generated correctly of explicit certificate for alg: ecdsaNistP256","pass":true,"statements":[]},"test_465":{"methods":[{"sl":34},{"sl":54}],"name":"Verify that getSignerIdentifier returns first signing certificate from a chain for type CERT_CHAIN","pass":true,"statements":[]},"test_482":{"methods":[{"sl":34},{"sl":54}],"name":"Verify that signed Ieee1609Dot2Data with hashed reference is generated correctly for alg: ecdsaNistP256","pass":true,"statements":[]},"test_485":{"methods":[{"sl":34},{"sl":54}],"name":"Verify that encryption works with secured data public encryption key for alg: ecdsaNistP256","pass":true,"statements":[]},"test_486":{"methods":[{"sl":34},{"sl":42},{"sl":54},{"sl":59}],"name":"Verify that constructor and getters are correct and it is correctly encoded","pass":true,"statements":[{"sl":44},{"sl":46},{"sl":48},{"sl":50}]},"test_498":{"methods":[{"sl":34},{"sl":54}],"name":"Verify that return first certificates public key of enroll cert only consists of implicit certificates","pass":true,"statements":[]},"test_499":{"methods":[{"sl":34},{"sl":54}],"name":"Verify that return first certificates public key of enroll cert and enroll ca consists of implicit certificates","pass":true,"statements":[]},"test_517":{"methods":[{"sl":34},{"sl":42},{"sl":54},{"sl":59}],"name":"Verify that SignerIdentifier is correctly encoded for type self","pass":true,"statements":[{"sl":44},{"sl":46},{"sl":48},{"sl":50}]},"test_521":{"methods":[{"sl":34},{"sl":42},{"sl":54},{"sl":59}],"name":"Verify that Ieee1609dot2Peer2PeerPDUContent is correctly encoded for type crl","pass":true,"statements":[{"sl":44},{"sl":46},{"sl":48},{"sl":50}]},"test_523":{"methods":[{"sl":34},{"sl":54}],"name":"Verify that Ieee1609Dot2 Enrollment Cert is generated correctly of implicit certificate for alg: ecdsaBrainpoolP256r1","pass":true,"statements":[]},"test_525":{"methods":[{"sl":34}],"name":"Verify that IllegalArgumentException is thrown when encoding if not all fields are set","pass":true,"statements":[]},"test_532":{"methods":[{"sl":34},{"sl":54}],"name":"Verify that getSignedDataStore returns an empty map if SignerIdentifier is digest","pass":true,"statements":[]},"test_54":{"methods":[{"sl":34}],"name":"Verify that IllegalArgumentException is thrown if none of required premissions doesn't exists for implicit certificate","pass":true,"statements":[]},"test_547":{"methods":[{"sl":34},{"sl":54}],"name":"Verify that buildRecieverStore generates a correct HashedId8 to Receiver Map","pass":true,"statements":[]},"test_548":{"methods":[{"sl":34},{"sl":37},{"sl":42}],"name":"Verify equals and hashcode","pass":true,"statements":[{"sl":39},{"sl":44},{"sl":46},{"sl":48},{"sl":50}]},"test_55":{"methods":[{"sl":34}],"name":"Verify that IllegalArgumentException is thrown if none of required premissions doesn't exists for explicit certificate","pass":true,"statements":[]},"test_557":{"methods":[{"sl":34},{"sl":42},{"sl":54},{"sl":59}],"name":"Verify that constructor and getters are correct and it is correctly encoded","pass":true,"statements":[{"sl":44},{"sl":46},{"sl":48},{"sl":50}]},"test_567":{"methods":[{"sl":34},{"sl":54}],"name":"Verify getCertID generates a correct HashedId8","pass":true,"statements":[]},"test_569":{"methods":[{"sl":34},{"sl":54}],"name":"Verify that encryption works with certificate public encryption key for alg: ecdsaNistP256","pass":true,"statements":[]},"test_587":{"methods":[{"sl":34},{"sl":54}],"name":"Verify that Ieee1609Dot2 Long term CA is generated correctly of explicit certificate for alg: ecdsaNistP256","pass":true,"statements":[]},"test_59":{"methods":[{"sl":34}],"name":"Verify that SignerIdentifier is correctly encoded for type digest","pass":true,"statements":[]},"test_608":{"methods":[{"sl":34},{"sl":54}],"name":"Verify that encryption works with secured data public encryption key for alg: ecdsaBrainpoolP256r1","pass":true,"statements":[]},"test_609":{"methods":[{"sl":34},{"sl":54}],"name":"Verify that Ieee1609Dot2 Short term CA is generated correctly of explicit certificate for alg: ecdsaNistP256","pass":true,"statements":[]},"test_616":{"methods":[{"sl":34}],"name":"Verify that reference structure from D.5.2.2 of P1909.2_D12 is parsed and regenerated correctly","pass":true,"statements":[]},"test_62":{"methods":[{"sl":34},{"sl":54}],"name":"Verify that Ieee1609Dot2 Long term CA is generated correctly of implicit certificate for alg: ecdsaNistP256","pass":true,"statements":[]},"test_625":{"methods":[{"sl":34},{"sl":54}],"name":"Verify that encryption works with RekReceipient for alg: ecdsaBrainpoolP256r1","pass":true,"statements":[]},"test_631":{"methods":[{"sl":34}],"name":"Verify toString()","pass":true,"statements":[]},"test_632":{"methods":[{"sl":34},{"sl":64}],"name":"Verify toString","pass":true,"statements":[{"sl":66}]},"test_637":{"methods":[{"sl":34}],"name":"Verify that IllegalArgumentException is thrown when encoding if not all fields are set","pass":true,"statements":[]},"test_646":{"methods":[{"sl":34},{"sl":42},{"sl":54},{"sl":59}],"name":"Verify that constructor and getters are correct and it is correctly encoded","pass":true,"statements":[{"sl":44},{"sl":46},{"sl":48},{"sl":50}]},"test_650":{"methods":[{"sl":34},{"sl":54}],"name":"Verify that buildCertStore() generates certificate store maps correctly and buildChain generates correct certificate chain","pass":true,"statements":[]},"test_654":{"methods":[{"sl":34},{"sl":42},{"sl":59}],"name":"Verify that SequenceOfPsidGroupPermissions is initialized properly","pass":true,"statements":[{"sl":44},{"sl":46},{"sl":48},{"sl":50}]},"test_665":{"methods":[{"sl":34},{"sl":54}],"name":"Verify that Ieee1609Dot2 Enrollment Cert is generated correctly of implicit certificate for alg: ecdsaNistP256","pass":true,"statements":[]},"test_670":{"methods":[{"sl":34}],"name":"Verify that SignerIdentifier is correctly encoded for type certificate","pass":true,"statements":[]},"test_681":{"methods":[{"sl":34}],"name":"Verify that getSignedDataStore returns an empty map if SignerIdentifier is self","pass":true,"statements":[]},"test_685":{"methods":[{"sl":34}],"name":"Verify that it is possible to parse the reference implicit certificate","pass":true,"statements":[]},"test_686":{"methods":[{"sl":34},{"sl":54}],"name":"Verify that signed SecuredCrl with signed data is generated correctly","pass":true,"statements":[]},"test_689":{"methods":[{"sl":34},{"sl":54}],"name":"Verify that Ieee1609Dot2 Root CA is generated correctly for explicit certificate (only type supported) for alg: ecdsaNistP256","pass":true,"statements":[]},"test_693":{"methods":[{"sl":34}],"name":"Verify that fullfillsRequirements verifies all required fields","pass":true,"statements":[]},"test_696":{"methods":[{"sl":34},{"sl":42},{"sl":54},{"sl":59}],"name":"Verify that SubjectPermissions is correctly encoded for type explicit","pass":true,"statements":[{"sl":44},{"sl":46},{"sl":48},{"sl":50}]},"test_708":{"methods":[{"sl":34}],"name":"Verify toString","pass":true,"statements":[]},"test_714":{"methods":[{"sl":34}],"name":"Verify that CertificateId is correctly encoded for type linkageData","pass":true,"statements":[]},"test_729":{"methods":[{"sl":34},{"sl":54}],"name":"Verify that Ieee1609Dot2 Long term CA is generated correctly of explicit certificate for alg: ecdsaBrainpoolP256r1","pass":true,"statements":[]},"test_735":{"methods":[{"sl":34},{"sl":54}],"name":"Verify that Ieee1609Dot2 Enrollment Cert is generated correctly for implicit CA certificate for alg: ecdsaNistP256","pass":true,"statements":[]},"test_74":{"methods":[{"sl":34},{"sl":54}],"name":"Verify that getSignedDataStore returns the HashedId8 of the first certificate if type is certificate","pass":true,"statements":[]},"test_746":{"methods":[{"sl":34}],"name":"Verify toString","pass":true,"statements":[]},"test_749":{"methods":[{"sl":34},{"sl":54}],"name":"Verify that Ieee1609Dot2 Enrollment Cert is generated correctly of implicit certificate for alg: ecdsaNistP256","pass":true,"statements":[]},"test_75":{"methods":[{"sl":34},{"sl":54}],"name":"Verify that signed Ieee1609Dot2Data with hashed reference is generated correctly for alg: ecdsaBrainpoolP256r1","pass":true,"statements":[]},"test_769":{"methods":[{"sl":34},{"sl":54}],"name":"Verify that Ieee1609Dot2 Enrollment Cert is generated correctly of explicit certificate for alg: ecdsaBrainpoolP256r1","pass":true,"statements":[]},"test_774":{"methods":[{"sl":34},{"sl":54}],"name":"Verify that signAndEncryptData and decryptAndVerifySignedData generates encrypted and signed data structures for alg: ecdsaBrainpoolP256r1","pass":true,"statements":[]},"test_78":{"methods":[{"sl":34}],"name":"Verify that getSignerId throws IllegalArgumentException if SignerIdentifier is self","pass":true,"statements":[]},"test_79":{"methods":[{"sl":34},{"sl":54}],"name":"Verify that Ieee1609Dot2 Enrollment Cert is generated correctly of implicit certificate for alg: ecdsaBrainpoolP256r1","pass":true,"statements":[]},"test_797":{"methods":[{"sl":34}],"name":"Verify toString","pass":true,"statements":[]},"test_818":{"methods":[{"sl":34}],"name":"Verify that SequenceOfCertificate is initialized properly","pass":true,"statements":[]},"test_829":{"methods":[{"sl":34},{"sl":54}],"name":"Verify that getSignerIdentifier returns correct hash value for type HASH_ONLY","pass":true,"statements":[]},"test_838":{"methods":[{"sl":34}],"name":"Verify constructor","pass":true,"statements":[]},"test_901":{"methods":[{"sl":34},{"sl":54}],"name":"Verify that Ieee1609Dot2 Short term CA is generated correctly of explicit certificate for alg: ecdsaBrainpoolP256r1","pass":true,"statements":[]},"test_939":{"methods":[{"sl":34}],"name":"Verify that IllegalArgumentException is thrown when encoding if not all fields are set","pass":true,"statements":[]},"test_942":{"methods":[{"sl":34}],"name":"Verify that constructor contains Ieee1609Dot2Data  if content  fullfill requirements","pass":true,"statements":[]},"test_946":{"methods":[{"sl":34},{"sl":54}],"name":"Verify that encryption works with RekReceipient for alg: ecdsaNistP256","pass":true,"statements":[]},"test_947":{"methods":[{"sl":34}],"name":"Verify toString","pass":true,"statements":[]},"test_955":{"methods":[{"sl":34}],"name":"Verify that  Ieee1609Dot2Content is correctly encoded for type signedData","pass":true,"statements":[]},"test_960":{"methods":[{"sl":34},{"sl":54}],"name":"Verify that Ieee1609Dot2 Authorization Cert is generated correctly of explicit certificate for alg: ecdsaBrainpoolP256r1","pass":true,"statements":[]},"test_974":{"methods":[{"sl":34}],"name":"Verify that constructor and getters are correct and it is correctly encoded","pass":true,"statements":[]}}

// JSON: { lines : [{tests : [testid1, testid2, testid3, ...]}, ...]};
clover.srcFileLines = [[], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [16, 625, 665, 422, 646, 239, 129, 637, 210, 249, 406, 631, 517, 168, 74, 960, 128, 226, 708, 686, 326, 670, 455, 974, 714, 685, 257, 59, 54, 62, 650, 632, 199, 261, 901, 838, 942, 532, 79, 947, 312, 75, 360, 939, 23, 654, 569, 829, 413, 525, 149, 608, 696, 609, 153, 43, 547, 587, 55, 325, 681, 387, 185, 246, 486, 769, 78, 417, 465, 482, 354, 136, 523, 689, 774, 749, 163, 693, 548, 616, 498, 485, 35, 735, 385, 557, 324, 373, 499, 818, 946, 729, 567, 746, 437, 248, 278, 172, 521, 0, 797, 955], [], [], [548], [], [548], [], [], [16, 422, 646, 517, 654, 149, 696, 153, 387, 486, 548, 557, 373, 437, 521], [], [16, 422, 646, 517, 654, 149, 696, 153, 387, 486, 548, 557, 373, 437, 521], [], [16, 422, 646, 517, 654, 149, 696, 153, 387, 486, 548, 557, 373, 437, 521], [], [16, 422, 646, 517, 654, 149, 696, 153, 387, 486, 548, 557, 373, 437, 521], [], [16, 422, 646, 517, 654, 149, 696, 153, 387, 486, 548, 557, 373, 437, 521], [], [], [], [16, 625, 665, 422, 646, 239, 129, 406, 517, 74, 960, 128, 226, 686, 455, 62, 650, 261, 901, 532, 79, 312, 75, 360, 23, 569, 829, 149, 608, 696, 609, 153, 547, 587, 486, 769, 465, 482, 354, 523, 689, 774, 749, 163, 498, 485, 35, 735, 385, 557, 324, 373, 499, 946, 729, 567, 437, 248, 278, 521, 0], [], [], [], [], [16, 422, 646, 129, 517, 23, 654, 149, 696, 153, 387, 486, 557, 373, 437, 521], [], [], [], [], [632], [], [632], [], []]
