var clover = new Object();

// JSON: {classes : [{name, id, sl, el,  methods : [{sl, el}, ...]}, ...]}
clover.pageData = {"classes":[{"el":40,"id":5442,"methods":[{"el":33,"sc":2,"sl":30},{"el":38,"sc":2,"sl":35}],"name":"SignedDataReciever","sl":26}]}

// JSON: {test_ID : {"methods": [ID1, ID2, ID3...], "name" : "testXXX() void"}, ...};
clover.testTargets = {"test_549":{"methods":[{"sl":30},{"sl":35}],"name":"Verify that encryption works with secured data public encryption key for alg: ecdsaBrainpoolP256r1","pass":true,"statements":[{"sl":31},{"sl":32},{"sl":37}]},"test_66":{"methods":[{"sl":30},{"sl":35}],"name":"Verify that buildRecieverStore generates a correct HashedId8 to Receiver Map","pass":true,"statements":[{"sl":31},{"sl":32},{"sl":37}]},"test_815":{"methods":[{"sl":30},{"sl":35}],"name":"Verify that encryption works with secured data public encryption key for alg: ecdsaNistP256","pass":true,"statements":[{"sl":31},{"sl":32},{"sl":37}]}}

// JSON: { lines : [{tests : [testid1, testid2, testid3, ...]}, ...]};
clover.srcFileLines = [[], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [66, 815, 549], [66, 815, 549], [66, 815, 549], [], [], [66, 815, 549], [], [66, 815, 549], [], [], []]
