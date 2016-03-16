var clover = new Object();

// JSON: {classes : [{name, id, sl, el,  methods : [{sl, el}, ...]}, ...]}
clover.pageData = {"classes":[{"el":85,"id":4258,"methods":[{"el":41,"sc":2,"sl":38},{"el":53,"sc":2,"sl":46},{"el":61,"sc":2,"sl":59},{"el":69,"sc":2,"sl":67},{"el":76,"sc":2,"sl":73},{"el":83,"sc":2,"sl":78}],"name":"EncryptedData","sl":27}]}

// JSON: {test_ID : {"methods": [ID1, ID2, ID3...], "name" : "testXXX() void"}, ...};
clover.testTargets = {"test_239":{"methods":[{"sl":46},{"sl":59},{"sl":67},{"sl":73}],"name":"Verify that encryption works with certificate public encryption key for alg: ecdsaBrainpoolP256r1","pass":true,"statements":[{"sl":47},{"sl":48},{"sl":50},{"sl":51},{"sl":60},{"sl":68},{"sl":74},{"sl":75}]},"test_286":{"methods":[{"sl":46},{"sl":59},{"sl":67},{"sl":73}],"name":"Verify that preshared key encryption works correctly","pass":true,"statements":[{"sl":47},{"sl":48},{"sl":50},{"sl":51},{"sl":60},{"sl":68},{"sl":74},{"sl":75}]},"test_289":{"methods":[{"sl":46},{"sl":59},{"sl":67},{"sl":73},{"sl":78}],"name":"Verify toString","pass":true,"statements":[{"sl":47},{"sl":48},{"sl":50},{"sl":51},{"sl":60},{"sl":68},{"sl":74},{"sl":75},{"sl":80}]},"test_304":{"methods":[{"sl":46},{"sl":59},{"sl":67},{"sl":73}],"name":"Verify that symmetric key envelope encryption works correctly","pass":true,"statements":[{"sl":47},{"sl":48},{"sl":50},{"sl":51},{"sl":60},{"sl":68},{"sl":74},{"sl":75}]},"test_35":{"methods":[{"sl":38},{"sl":46},{"sl":59},{"sl":67},{"sl":73}],"name":"Verify that signAndEncryptData and decryptAndVerifySignedData generates encrypted and signed data structures for alg: ecdsaNistP256","pass":true,"statements":[{"sl":39},{"sl":40},{"sl":47},{"sl":48},{"sl":50},{"sl":51},{"sl":60},{"sl":68},{"sl":74},{"sl":75}]},"test_396":{"methods":[{"sl":38},{"sl":46},{"sl":59},{"sl":67},{"sl":73}],"name":"Verify that constructor and getters are correct and it is correctly encoded","pass":true,"statements":[{"sl":39},{"sl":40},{"sl":47},{"sl":48},{"sl":50},{"sl":51},{"sl":60},{"sl":68},{"sl":74},{"sl":75}]},"test_413":{"methods":[{"sl":46},{"sl":73}],"name":"Verify that fullfillsRequirements verifies all required fields","pass":true,"statements":[{"sl":47},{"sl":48},{"sl":50},{"sl":51},{"sl":74},{"sl":75}]},"test_418":{"methods":[{"sl":46},{"sl":73}],"name":"Verify that IllegalArgumentException is thrown when encoding if not all fields are set","pass":true,"statements":[{"sl":47},{"sl":48},{"sl":50},{"sl":51},{"sl":74},{"sl":75}]},"test_460":{"methods":[{"sl":38},{"sl":73}],"name":"Verify that  Ieee1609Dot2Content is correctly encoded for type encryptedData","pass":true,"statements":[{"sl":39},{"sl":40},{"sl":74},{"sl":75}]},"test_485":{"methods":[{"sl":46},{"sl":59},{"sl":67},{"sl":73}],"name":"Verify that encryption works with secured data public encryption key for alg: ecdsaNistP256","pass":true,"statements":[{"sl":47},{"sl":48},{"sl":50},{"sl":51},{"sl":60},{"sl":68},{"sl":74},{"sl":75}]},"test_569":{"methods":[{"sl":46},{"sl":59},{"sl":67},{"sl":73}],"name":"Verify that encryption works with certificate public encryption key for alg: ecdsaNistP256","pass":true,"statements":[{"sl":47},{"sl":48},{"sl":50},{"sl":51},{"sl":60},{"sl":68},{"sl":74},{"sl":75}]},"test_608":{"methods":[{"sl":46},{"sl":59},{"sl":67},{"sl":73}],"name":"Verify that encryption works with secured data public encryption key for alg: ecdsaBrainpoolP256r1","pass":true,"statements":[{"sl":47},{"sl":48},{"sl":50},{"sl":51},{"sl":60},{"sl":68},{"sl":74},{"sl":75}]},"test_625":{"methods":[{"sl":46},{"sl":59},{"sl":67},{"sl":73}],"name":"Verify that encryption works with RekReceipient for alg: ecdsaBrainpoolP256r1","pass":true,"statements":[{"sl":47},{"sl":48},{"sl":50},{"sl":51},{"sl":60},{"sl":68},{"sl":74},{"sl":75}]},"test_693":{"methods":[{"sl":46},{"sl":73}],"name":"Verify that fullfillsRequirements verifies all required fields","pass":true,"statements":[{"sl":47},{"sl":48},{"sl":50},{"sl":51},{"sl":74},{"sl":75}]},"test_774":{"methods":[{"sl":38},{"sl":46},{"sl":59},{"sl":67},{"sl":73}],"name":"Verify that signAndEncryptData and decryptAndVerifySignedData generates encrypted and signed data structures for alg: ecdsaBrainpoolP256r1","pass":true,"statements":[{"sl":39},{"sl":40},{"sl":47},{"sl":48},{"sl":50},{"sl":51},{"sl":60},{"sl":68},{"sl":74},{"sl":75}]},"test_946":{"methods":[{"sl":46},{"sl":59},{"sl":67},{"sl":73}],"name":"Verify that encryption works with RekReceipient for alg: ecdsaNistP256","pass":true,"statements":[{"sl":47},{"sl":48},{"sl":50},{"sl":51},{"sl":60},{"sl":68},{"sl":74},{"sl":75}]}}

// JSON: { lines : [{tests : [testid1, testid2, testid3, ...]}, ...]};
clover.srcFileLines = [[], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [35, 460, 396, 774], [35, 460, 396, 774], [35, 460, 396, 774], [], [], [], [], [], [946, 35, 625, 239, 569, 418, 396, 286, 413, 304, 774, 608, 693, 289, 485], [946, 35, 625, 239, 569, 418, 396, 286, 413, 304, 774, 608, 693, 289, 485], [946, 35, 625, 239, 569, 418, 396, 286, 413, 304, 774, 608, 693, 289, 485], [], [946, 35, 625, 239, 569, 418, 396, 286, 413, 304, 774, 608, 693, 289, 485], [946, 35, 625, 239, 569, 418, 396, 286, 413, 304, 774, 608, 693, 289, 485], [], [], [], [], [], [], [], [946, 35, 625, 239, 569, 396, 286, 304, 774, 608, 289, 485], [946, 35, 625, 239, 569, 396, 286, 304, 774, 608, 289, 485], [], [], [], [], [], [], [946, 35, 625, 239, 569, 396, 286, 304, 774, 608, 289, 485], [946, 35, 625, 239, 569, 396, 286, 304, 774, 608, 289, 485], [], [], [], [], [946, 35, 625, 239, 569, 418, 460, 396, 286, 413, 304, 774, 608, 693, 289, 485], [946, 35, 625, 239, 569, 418, 460, 396, 286, 413, 304, 774, 608, 693, 289, 485], [946, 35, 625, 239, 569, 418, 460, 396, 286, 413, 304, 774, 608, 693, 289, 485], [], [], [289], [], [289], [], [], [], [], []]
