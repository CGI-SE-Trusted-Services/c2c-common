var clover = new Object();

// JSON: {classes : [{name, id, sl, el,  methods : [{sl, el}, ...]}, ...]}
clover.pageData = {"classes":[{"el":47,"id":5278,"methods":[{"el":39,"sc":2,"sl":36},{"el":44,"sc":2,"sl":41}],"name":"CertificateReciever","sl":26}]}

// JSON: {test_ID : {"methods": [ID1, ID2, ID3...], "name" : "testXXX() void"}, ...};
clover.testTargets = {"test_239":{"methods":[{"sl":36},{"sl":41}],"name":"Verify that encryption works with certificate public encryption key for alg: ecdsaBrainpoolP256r1","pass":true,"statements":[{"sl":37},{"sl":38},{"sl":43}]},"test_35":{"methods":[{"sl":36},{"sl":41}],"name":"Verify that signAndEncryptData and decryptAndVerifySignedData generates encrypted and signed data structures for alg: ecdsaNistP256","pass":true,"statements":[{"sl":37},{"sl":38},{"sl":43}]},"test_547":{"methods":[{"sl":36},{"sl":41}],"name":"Verify that buildRecieverStore generates a correct HashedId8 to Receiver Map","pass":true,"statements":[{"sl":37},{"sl":38},{"sl":43}]},"test_569":{"methods":[{"sl":36},{"sl":41}],"name":"Verify that encryption works with certificate public encryption key for alg: ecdsaNistP256","pass":true,"statements":[{"sl":37},{"sl":38},{"sl":43}]},"test_774":{"methods":[{"sl":36},{"sl":41}],"name":"Verify that signAndEncryptData and decryptAndVerifySignedData generates encrypted and signed data structures for alg: ecdsaBrainpoolP256r1","pass":true,"statements":[{"sl":37},{"sl":38},{"sl":43}]}}

// JSON: { lines : [{tests : [testid1, testid2, testid3, ...]}, ...]};
clover.srcFileLines = [[], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [35, 569, 547, 774, 239], [35, 569, 547, 774, 239], [35, 569, 547, 774, 239], [], [], [35, 569, 547, 774, 239], [], [35, 569, 547, 774, 239], [], [], [], []]
