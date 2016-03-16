var clover = new Object();

// JSON: {classes : [{name, id, sl, el,  methods : [{sl, el}, ...]}, ...]}
clover.pageData = {"classes":[{"el":110,"id":3428,"methods":[{"el":69,"sc":2,"sl":67},{"el":76,"sc":2,"sl":74},{"el":83,"sc":2,"sl":81},{"el":90,"sc":2,"sl":88},{"el":97,"sc":2,"sl":92},{"el":108,"sc":2,"sl":99}],"name":"IssuerIdentifier","sl":43},{"el":62,"id":3428,"methods":[{"el":61,"sc":3,"sl":52}],"name":"IssuerIdentifier.IssuerIdentifierChoices","sl":48}]}

// JSON: {test_ID : {"methods": [ID1, ID2, ID3...], "name" : "testXXX() void"}, ...};
clover.testTargets = {"test_0":{"methods":[{"sl":67},{"sl":74},{"sl":81},{"sl":88}],"name":"Verify that Ieee1609Dot2 Authorization Cert is generated correctly of explicit certificate for alg: ecdsaNistP256","pass":true,"statements":[{"sl":68},{"sl":75},{"sl":82},{"sl":89}]},"test_128":{"methods":[{"sl":67},{"sl":74},{"sl":81}],"name":"Verify that getSignerIdentifier returns first signing certificate from a chain for type SIGNER_CERTIFICATE","pass":true,"statements":[{"sl":68},{"sl":75},{"sl":82}]},"test_136":{"methods":[{"sl":52},{"sl":81}],"name":"Verify that Ieee1609dot2Peer2PeerPDUContent is correctly encoded for type caCerts","pass":true,"statements":[{"sl":54},{"sl":57},{"sl":59},{"sl":82}]},"test_16":{"methods":[{"sl":52},{"sl":81}],"name":"Verify that constructor and getters are correct and it is correctly encoded for implicit certificates","pass":true,"statements":[{"sl":54},{"sl":57},{"sl":59},{"sl":82}]},"test_163":{"methods":[{"sl":67},{"sl":74},{"sl":81}],"name":"Verify that Ieee1609Dot2 Long term CA is generated correctly of implicit certificate for alg: ecdsaBrainpoolP256r1","pass":true,"statements":[{"sl":68},{"sl":75},{"sl":82}]},"test_172":{"methods":[{"sl":81},{"sl":88},{"sl":92},{"sl":99}],"name":"Verify toString","pass":true,"statements":[{"sl":82},{"sl":89},{"sl":93},{"sl":94},{"sl":101},{"sl":104},{"sl":106}]},"test_185":{"methods":[{"sl":81},{"sl":88},{"sl":92},{"sl":99}],"name":"Verify toString","pass":true,"statements":[{"sl":82},{"sl":89},{"sl":93},{"sl":94},{"sl":101},{"sl":104},{"sl":106}]},"test_226":{"methods":[{"sl":67},{"sl":74},{"sl":81}],"name":"Verify that Ieee1609Dot2 Enrollment Cert is generated correctly for implicit CA certificate for alg: ecdsaBrainpoolP256r1","pass":true,"statements":[{"sl":68},{"sl":75},{"sl":82}]},"test_239":{"methods":[{"sl":67},{"sl":74},{"sl":81}],"name":"Verify that encryption works with certificate public encryption key for alg: ecdsaBrainpoolP256r1","pass":true,"statements":[{"sl":68},{"sl":75},{"sl":82}]},"test_248":{"methods":[{"sl":67},{"sl":74},{"sl":81}],"name":"Verify that getSignedDataStore returns a populate map of all certificate if SignerIdentifier is certificate","pass":true,"statements":[{"sl":68},{"sl":75},{"sl":82}]},"test_261":{"methods":[{"sl":67},{"sl":74},{"sl":81}],"name":"Verify that return first certificates public key of complete chain consists of explicit certificates","pass":true,"statements":[{"sl":68},{"sl":75},{"sl":82}]},"test_276":{"methods":[{"sl":52},{"sl":67},{"sl":81},{"sl":88}],"name":"Verify that IssuerIdentifier is correctly encoded for type sha256AndDigest","pass":true,"statements":[{"sl":54},{"sl":55},{"sl":56},{"sl":68},{"sl":82},{"sl":89}]},"test_278":{"methods":[{"sl":67},{"sl":74},{"sl":81}],"name":"Verify that Ieee1609Dot2 Enrollment Cert is generated correctly for implicit CA certificate for alg: ecdsaBrainpoolP256r1","pass":true,"statements":[{"sl":68},{"sl":75},{"sl":82}]},"test_312":{"methods":[{"sl":67},{"sl":74},{"sl":81}],"name":"Verify that findFromStores finds certificate from stores","pass":true,"statements":[{"sl":68},{"sl":75},{"sl":82}]},"test_324":{"methods":[{"sl":74},{"sl":81}],"name":"Verify that getSignerId returns the included HashedId8 if type is digest","pass":true,"statements":[{"sl":75},{"sl":82}]},"test_326":{"methods":[{"sl":88},{"sl":92},{"sl":99}],"name":"Verify toString","pass":true,"statements":[{"sl":89},{"sl":93},{"sl":94},{"sl":101},{"sl":104},{"sl":106}]},"test_35":{"methods":[{"sl":67},{"sl":74},{"sl":81},{"sl":88}],"name":"Verify that signAndEncryptData and decryptAndVerifySignedData generates encrypted and signed data structures for alg: ecdsaNistP256","pass":true,"statements":[{"sl":68},{"sl":75},{"sl":82},{"sl":89}]},"test_354":{"methods":[{"sl":74},{"sl":81},{"sl":88}],"name":"Verify that Ieee1609Dot2 Root CA is generated correctly for explicit certificate (only type supported) for alg: ecdsaBrainpoolP256r1","pass":true,"statements":[{"sl":75},{"sl":82},{"sl":89}]},"test_360":{"methods":[{"sl":67},{"sl":74},{"sl":81}],"name":"Verify that Ieee1609Dot2 Enrollment Cert is generated correctly for implicit CA certificate for alg: ecdsaNistP256","pass":true,"statements":[{"sl":68},{"sl":75},{"sl":82}]},"test_385":{"methods":[{"sl":67},{"sl":74},{"sl":81},{"sl":88}],"name":"Verify that signed Ieee1609Dot2Data with signed data is generated correctly for alg: ecdsaBrainpoolP256r1","pass":true,"statements":[{"sl":68},{"sl":75},{"sl":82},{"sl":89}]},"test_406":{"methods":[{"sl":67},{"sl":74},{"sl":81},{"sl":88}],"name":"Verify that signed Ieee1609Dot2Data with signed data is generated correctly for alg: ecdsaNistP256","pass":true,"statements":[{"sl":68},{"sl":75},{"sl":82},{"sl":89}]},"test_417":{"methods":[{"sl":52},{"sl":81}],"name":"Verify that CaCertP2pPDU is initialized properly","pass":true,"statements":[{"sl":54},{"sl":57},{"sl":59},{"sl":82}]},"test_435":{"methods":[{"sl":67},{"sl":74},{"sl":88},{"sl":92},{"sl":99}],"name":"Verify toString","pass":true,"statements":[{"sl":68},{"sl":75},{"sl":89},{"sl":93},{"sl":94},{"sl":101},{"sl":102},{"sl":103},{"sl":104},{"sl":106}]},"test_437":{"methods":[{"sl":52},{"sl":81}],"name":"Verify that constructor and getters are correct and it is correctly encoded for explicit certificates","pass":true,"statements":[{"sl":54},{"sl":57},{"sl":59},{"sl":82}]},"test_455":{"methods":[{"sl":67},{"sl":74},{"sl":81},{"sl":88}],"name":"Verify that Ieee1609Dot2 Enrollment Cert is generated correctly of explicit certificate for alg: ecdsaNistP256","pass":true,"statements":[{"sl":68},{"sl":75},{"sl":82},{"sl":89}]},"test_465":{"methods":[{"sl":67},{"sl":74},{"sl":81}],"name":"Verify that getSignerIdentifier returns first signing certificate from a chain for type CERT_CHAIN","pass":true,"statements":[{"sl":68},{"sl":75},{"sl":82}]},"test_482":{"methods":[{"sl":67},{"sl":74},{"sl":81},{"sl":88}],"name":"Verify that signed Ieee1609Dot2Data with hashed reference is generated correctly for alg: ecdsaNistP256","pass":true,"statements":[{"sl":68},{"sl":75},{"sl":82},{"sl":89}]},"test_485":{"methods":[{"sl":67},{"sl":74},{"sl":81}],"name":"Verify that encryption works with secured data public encryption key for alg: ecdsaNistP256","pass":true,"statements":[{"sl":68},{"sl":75},{"sl":82}]},"test_498":{"methods":[{"sl":67},{"sl":74},{"sl":81}],"name":"Verify that return first certificates public key of enroll cert only consists of implicit certificates","pass":true,"statements":[{"sl":68},{"sl":75},{"sl":82}]},"test_499":{"methods":[{"sl":67},{"sl":74},{"sl":81}],"name":"Verify that return first certificates public key of enroll cert and enroll ca consists of implicit certificates","pass":true,"statements":[{"sl":68},{"sl":75},{"sl":82}]},"test_523":{"methods":[{"sl":67},{"sl":74},{"sl":81}],"name":"Verify that Ieee1609Dot2 Enrollment Cert is generated correctly of implicit certificate for alg: ecdsaBrainpoolP256r1","pass":true,"statements":[{"sl":68},{"sl":75},{"sl":82}]},"test_532":{"methods":[{"sl":74},{"sl":81}],"name":"Verify that getSignedDataStore returns an empty map if SignerIdentifier is digest","pass":true,"statements":[{"sl":75},{"sl":82}]},"test_54":{"methods":[{"sl":81}],"name":"Verify that IllegalArgumentException is thrown if none of required premissions doesn't exists for implicit certificate","pass":true,"statements":[{"sl":82}]},"test_547":{"methods":[{"sl":74},{"sl":81}],"name":"Verify that buildRecieverStore generates a correct HashedId8 to Receiver Map","pass":true,"statements":[{"sl":75},{"sl":82}]},"test_55":{"methods":[{"sl":81}],"name":"Verify that IllegalArgumentException is thrown if none of required premissions doesn't exists for explicit certificate","pass":true,"statements":[{"sl":82}]},"test_567":{"methods":[{"sl":74},{"sl":81}],"name":"Verify getCertID generates a correct HashedId8","pass":true,"statements":[{"sl":75},{"sl":82}]},"test_569":{"methods":[{"sl":67},{"sl":74},{"sl":81}],"name":"Verify that encryption works with certificate public encryption key for alg: ecdsaNistP256","pass":true,"statements":[{"sl":68},{"sl":75},{"sl":82}]},"test_587":{"methods":[{"sl":67},{"sl":74},{"sl":81},{"sl":88}],"name":"Verify that Ieee1609Dot2 Long term CA is generated correctly of explicit certificate for alg: ecdsaNistP256","pass":true,"statements":[{"sl":68},{"sl":75},{"sl":82},{"sl":89}]},"test_608":{"methods":[{"sl":67},{"sl":74},{"sl":81}],"name":"Verify that encryption works with secured data public encryption key for alg: ecdsaBrainpoolP256r1","pass":true,"statements":[{"sl":68},{"sl":75},{"sl":82}]},"test_609":{"methods":[{"sl":67},{"sl":74},{"sl":81}],"name":"Verify that Ieee1609Dot2 Short term CA is generated correctly of explicit certificate for alg: ecdsaNistP256","pass":true,"statements":[{"sl":68},{"sl":75},{"sl":82}]},"test_616":{"methods":[{"sl":52},{"sl":81},{"sl":88},{"sl":99}],"name":"Verify that reference structure from D.5.2.2 of P1909.2_D12 is parsed and regenerated correctly","pass":true,"statements":[{"sl":54},{"sl":55},{"sl":56},{"sl":82},{"sl":89},{"sl":101},{"sl":102},{"sl":103}]},"test_618":{"methods":[{"sl":52},{"sl":74},{"sl":81},{"sl":88},{"sl":92}],"name":"Verify that IssuerIdentifier is correctly encoded for type self","pass":true,"statements":[{"sl":54},{"sl":57},{"sl":59},{"sl":75},{"sl":82},{"sl":89},{"sl":93},{"sl":94}]},"test_62":{"methods":[{"sl":67},{"sl":74},{"sl":81}],"name":"Verify that Ieee1609Dot2 Long term CA is generated correctly of implicit certificate for alg: ecdsaNistP256","pass":true,"statements":[{"sl":68},{"sl":75},{"sl":82}]},"test_625":{"methods":[{"sl":67},{"sl":74},{"sl":81}],"name":"Verify that encryption works with RekReceipient for alg: ecdsaBrainpoolP256r1","pass":true,"statements":[{"sl":68},{"sl":75},{"sl":82}]},"test_650":{"methods":[{"sl":67},{"sl":74},{"sl":81},{"sl":88}],"name":"Verify that buildCertStore() generates certificate store maps correctly and buildChain generates correct certificate chain","pass":true,"statements":[{"sl":68},{"sl":75},{"sl":82},{"sl":89}]},"test_665":{"methods":[{"sl":67},{"sl":74},{"sl":81}],"name":"Verify that Ieee1609Dot2 Enrollment Cert is generated correctly of implicit certificate for alg: ecdsaNistP256","pass":true,"statements":[{"sl":68},{"sl":75},{"sl":82}]},"test_670":{"methods":[{"sl":52},{"sl":81}],"name":"Verify that SignerIdentifier is correctly encoded for type certificate","pass":true,"statements":[{"sl":54},{"sl":57},{"sl":59},{"sl":82}]},"test_685":{"methods":[{"sl":52},{"sl":81},{"sl":88},{"sl":99}],"name":"Verify that it is possible to parse the reference implicit certificate","pass":true,"statements":[{"sl":54},{"sl":55},{"sl":56},{"sl":82},{"sl":89},{"sl":101},{"sl":102},{"sl":103}]},"test_686":{"methods":[{"sl":67},{"sl":74},{"sl":81},{"sl":88}],"name":"Verify that signed SecuredCrl with signed data is generated correctly","pass":true,"statements":[{"sl":68},{"sl":75},{"sl":82},{"sl":89}]},"test_689":{"methods":[{"sl":74},{"sl":81},{"sl":88}],"name":"Verify that Ieee1609Dot2 Root CA is generated correctly for explicit certificate (only type supported) for alg: ecdsaNistP256","pass":true,"statements":[{"sl":75},{"sl":82},{"sl":89}]},"test_708":{"methods":[{"sl":88},{"sl":92},{"sl":99}],"name":"Verify toString","pass":true,"statements":[{"sl":89},{"sl":93},{"sl":94},{"sl":101},{"sl":104},{"sl":106}]},"test_729":{"methods":[{"sl":67},{"sl":74},{"sl":81},{"sl":88}],"name":"Verify that Ieee1609Dot2 Long term CA is generated correctly of explicit certificate for alg: ecdsaBrainpoolP256r1","pass":true,"statements":[{"sl":68},{"sl":75},{"sl":82},{"sl":89}]},"test_735":{"methods":[{"sl":67},{"sl":74},{"sl":81}],"name":"Verify that Ieee1609Dot2 Enrollment Cert is generated correctly for implicit CA certificate for alg: ecdsaNistP256","pass":true,"statements":[{"sl":68},{"sl":75},{"sl":82}]},"test_74":{"methods":[{"sl":67},{"sl":74},{"sl":81}],"name":"Verify that getSignedDataStore returns the HashedId8 of the first certificate if type is certificate","pass":true,"statements":[{"sl":68},{"sl":75},{"sl":82}]},"test_749":{"methods":[{"sl":67},{"sl":74},{"sl":81}],"name":"Verify that Ieee1609Dot2 Enrollment Cert is generated correctly of implicit certificate for alg: ecdsaNistP256","pass":true,"statements":[{"sl":68},{"sl":75},{"sl":82}]},"test_75":{"methods":[{"sl":67},{"sl":74},{"sl":81},{"sl":88}],"name":"Verify that signed Ieee1609Dot2Data with hashed reference is generated correctly for alg: ecdsaBrainpoolP256r1","pass":true,"statements":[{"sl":68},{"sl":75},{"sl":82},{"sl":89}]},"test_756":{"methods":[{"sl":88},{"sl":92},{"sl":99}],"name":"Verify toString()","pass":true,"statements":[{"sl":89},{"sl":93},{"sl":94},{"sl":101},{"sl":104},{"sl":106}]},"test_769":{"methods":[{"sl":67},{"sl":74},{"sl":81},{"sl":88}],"name":"Verify that Ieee1609Dot2 Enrollment Cert is generated correctly of explicit certificate for alg: ecdsaBrainpoolP256r1","pass":true,"statements":[{"sl":68},{"sl":75},{"sl":82},{"sl":89}]},"test_774":{"methods":[{"sl":67},{"sl":74},{"sl":81},{"sl":88}],"name":"Verify that signAndEncryptData and decryptAndVerifySignedData generates encrypted and signed data structures for alg: ecdsaBrainpoolP256r1","pass":true,"statements":[{"sl":68},{"sl":75},{"sl":82},{"sl":89}]},"test_79":{"methods":[{"sl":67},{"sl":74},{"sl":81}],"name":"Verify that Ieee1609Dot2 Enrollment Cert is generated correctly of implicit certificate for alg: ecdsaBrainpoolP256r1","pass":true,"statements":[{"sl":68},{"sl":75},{"sl":82}]},"test_818":{"methods":[{"sl":52},{"sl":81}],"name":"Verify that SequenceOfCertificate is initialized properly","pass":true,"statements":[{"sl":54},{"sl":57},{"sl":59},{"sl":82}]},"test_829":{"methods":[{"sl":74},{"sl":81}],"name":"Verify that getSignerIdentifier returns correct hash value for type HASH_ONLY","pass":true,"statements":[{"sl":75},{"sl":82}]},"test_901":{"methods":[{"sl":67},{"sl":74},{"sl":81}],"name":"Verify that Ieee1609Dot2 Short term CA is generated correctly of explicit certificate for alg: ecdsaBrainpoolP256r1","pass":true,"statements":[{"sl":68},{"sl":75},{"sl":82}]},"test_939":{"methods":[{"sl":81}],"name":"Verify that IllegalArgumentException is thrown when encoding if not all fields are set","pass":true,"statements":[{"sl":82}]},"test_946":{"methods":[{"sl":67},{"sl":74},{"sl":81}],"name":"Verify that encryption works with RekReceipient for alg: ecdsaNistP256","pass":true,"statements":[{"sl":68},{"sl":75},{"sl":82}]},"test_947":{"methods":[{"sl":81},{"sl":88},{"sl":92},{"sl":99}],"name":"Verify toString","pass":true,"statements":[{"sl":82},{"sl":89},{"sl":93},{"sl":94},{"sl":101},{"sl":104},{"sl":106}]},"test_960":{"methods":[{"sl":67},{"sl":74},{"sl":81},{"sl":88}],"name":"Verify that Ieee1609Dot2 Authorization Cert is generated correctly of explicit certificate for alg: ecdsaBrainpoolP256r1","pass":true,"statements":[{"sl":68},{"sl":75},{"sl":82},{"sl":89}]}}

// JSON: { lines : [{tests : [testid1, testid2, testid3, ...]}, ...]};
clover.srcFileLines = [[], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [16, 417, 276, 818, 670, 136, 437, 685, 618, 616], [], [16, 417, 276, 818, 670, 136, 437, 685, 618, 616], [276, 685, 616], [276, 685, 616], [16, 417, 818, 670, 136, 437, 618], [], [16, 417, 818, 670, 136, 437, 618], [], [], [], [], [], [], [], [261, 35, 625, 435, 901, 587, 665, 239, 735, 385, 79, 312, 406, 75, 360, 769, 74, 960, 128, 226, 499, 465, 276, 482, 946, 686, 455, 729, 569, 523, 248, 774, 749, 278, 163, 608, 62, 650, 0, 498, 609, 485], [261, 35, 625, 435, 901, 587, 665, 239, 735, 385, 79, 312, 406, 75, 360, 769, 74, 960, 128, 226, 499, 465, 276, 482, 946, 686, 455, 729, 569, 523, 248, 774, 749, 278, 163, 608, 62, 650, 0, 498, 609, 485], [], [], [], [], [], [261, 35, 625, 435, 901, 547, 587, 665, 239, 735, 385, 532, 79, 324, 312, 406, 75, 360, 769, 74, 960, 128, 226, 499, 465, 482, 946, 686, 354, 455, 729, 567, 569, 829, 523, 689, 248, 618, 774, 749, 278, 163, 608, 62, 650, 0, 498, 609, 485], [261, 35, 625, 435, 901, 547, 587, 665, 239, 735, 385, 532, 79, 324, 312, 406, 75, 360, 769, 74, 960, 128, 226, 499, 465, 482, 946, 686, 354, 455, 729, 567, 569, 829, 523, 689, 248, 618, 774, 749, 278, 163, 608, 62, 650, 0, 498, 609, 485], [], [], [], [], [], [16, 261, 35, 625, 901, 547, 587, 665, 55, 239, 735, 385, 532, 79, 324, 947, 312, 406, 185, 75, 360, 939, 769, 74, 960, 417, 128, 226, 499, 465, 276, 482, 818, 946, 686, 354, 670, 136, 455, 729, 567, 569, 829, 437, 523, 685, 689, 248, 618, 774, 749, 278, 163, 54, 608, 172, 62, 650, 616, 0, 498, 609, 485], [16, 261, 35, 625, 901, 547, 587, 665, 55, 239, 735, 385, 532, 79, 324, 947, 312, 406, 185, 75, 360, 939, 769, 74, 960, 417, 128, 226, 499, 465, 276, 482, 818, 946, 686, 354, 670, 136, 455, 729, 567, 569, 829, 437, 523, 685, 689, 248, 618, 774, 749, 278, 163, 54, 608, 172, 62, 650, 616, 0, 498, 609, 485], [], [], [], [], [], [35, 435, 587, 385, 756, 947, 406, 185, 75, 769, 960, 276, 482, 708, 686, 326, 354, 455, 729, 685, 689, 618, 774, 172, 650, 616, 0], [35, 435, 587, 385, 756, 947, 406, 185, 75, 769, 960, 276, 482, 708, 686, 326, 354, 455, 729, 685, 689, 618, 774, 172, 650, 616, 0], [], [], [435, 756, 947, 185, 708, 326, 618, 172], [435, 756, 947, 185, 708, 326, 618, 172], [435, 756, 947, 185, 708, 326, 618, 172], [], [], [], [], [435, 756, 947, 185, 708, 326, 685, 172, 616], [], [435, 756, 947, 185, 708, 326, 685, 172, 616], [435, 685, 616], [435, 685, 616], [435, 756, 947, 185, 708, 326, 172], [], [435, 756, 947, 185, 708, 326, 172], [], [], [], []]
