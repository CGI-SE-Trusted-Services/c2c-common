var clover = new Object();

// JSON: {classes : [{name, id, sl, el,  methods : [{sl, el}, ...]}, ...]}
clover.pageData = {"classes":[{"el":57,"id":5434,"methods":[{"el":41,"sc":2,"sl":38},{"el":50,"sc":2,"sl":43},{"el":55,"sc":2,"sl":52}],"name":"RekReciever","sl":34}]}

// JSON: {test_ID : {"methods": [ID1, ID2, ID3...], "name" : "testXXX() void"}, ...};
clover.testTargets = {"test_321":{"methods":[{"sl":38},{"sl":43},{"sl":52}],"name":"Verify that encryption works with RekReceipient for alg: ecdsaNistP256","pass":true,"statements":[{"sl":39},{"sl":40},{"sl":48},{"sl":49},{"sl":54}]},"test_66":{"methods":[{"sl":38},{"sl":52}],"name":"Verify that buildRecieverStore generates a correct HashedId8 to Receiver Map","pass":true,"statements":[{"sl":39},{"sl":40},{"sl":54}]},"test_825":{"methods":[{"sl":38},{"sl":43},{"sl":52}],"name":"Verify that encryption works with RekReceipient for alg: ecdsaBrainpoolP256r1","pass":true,"statements":[{"sl":39},{"sl":40},{"sl":48},{"sl":49},{"sl":54}]}}

// JSON: { lines : [{tests : [testid1, testid2, testid3, ...]}, ...]};
clover.srcFileLines = [[], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [321, 66, 825], [321, 66, 825], [321, 66, 825], [], [], [321, 825], [], [], [], [], [321, 825], [321, 825], [], [], [321, 66, 825], [], [321, 66, 825], [], [], []]
