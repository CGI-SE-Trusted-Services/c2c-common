var clover = new Object();

// JSON: {classes : [{name, id, sl, el,  methods : [{sl, el}, ...]}, ...]}
clover.pageData = {"classes":[{"el":74,"id":5200,"methods":[{"el":48,"sc":2,"sl":32},{"el":62,"sc":2,"sl":57},{"el":73,"sc":2,"sl":64}],"name":"PublicKeyAlgorithmSpec","sl":30}]}

// JSON: {test_ID : {"methods": [ID1, ID2, ID3...], "name" : "testXXX() void"}, ...};
clover.testTargets = {"test_138":{"methods":[{"sl":32}],"name":"Verify that ecies_nistp256 has bytevalue 1","pass":true,"statements":[{"sl":35},{"sl":36},{"sl":37},{"sl":40},{"sl":41}]},"test_278":{"methods":[{"sl":32}],"name":"Verify that ecdsa_nistp256_with_sha256 has bytevalue 0","pass":true,"statements":[{"sl":35},{"sl":36},{"sl":37},{"sl":38},{"sl":40}]},"test_326":{"methods":[{"sl":57}],"name":"Verify that UnsupportedOperationException is thrown for a public key with unsupported related symmetric algorithm","pass":true,"statements":[{"sl":59},{"sl":61}]},"test_9":{"methods":[{"sl":64}],"name":"Verify that PublicKeyAlgorithm.getByValue returns ecies_nistp256 for 1","pass":true,"statements":[{"sl":67}]},"test_94":{"methods":[{"sl":64}],"name":"Verify that PublicKeyAlgorithm.getByValue returns ecdsa_nistp256_with_sha256 for 0","pass":true,"statements":[{"sl":67}]}}

// JSON: { lines : [{tests : [testid1, testid2, testid3, ...]}, ...]};
clover.srcFileLines = [[], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [138, 278], [], [], [138, 278], [138, 278], [138, 278], [278], [], [138, 278], [138], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [326], [], [326], [], [326], [], [], [9, 94], [], [], [9, 94], [], [], [], [], [], [], []]
