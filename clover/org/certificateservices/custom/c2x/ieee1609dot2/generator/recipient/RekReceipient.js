var clover = new Object();

// JSON: {classes : [{name, id, sl, el,  methods : [{sl, el}, ...]}, ...]}
clover.pageData = {"classes":[{"el":57,"id":5481,"methods":[{"el":44,"sc":2,"sl":42},{"el":56,"sc":2,"sl":46}],"name":"RekReceipient","sl":38}]}

// JSON: {test_ID : {"methods": [ID1, ID2, ID3...], "name" : "testXXX() void"}, ...};
clover.testTargets = {"test_321":{"methods":[{"sl":42},{"sl":46}],"name":"Verify that encryption works with RekReceipient for alg: ecdsaNistP256","pass":true,"statements":[{"sl":43},{"sl":51},{"sl":52},{"sl":54},{"sl":55}]},"test_825":{"methods":[{"sl":42},{"sl":46}],"name":"Verify that encryption works with RekReceipient for alg: ecdsaBrainpoolP256r1","pass":true,"statements":[{"sl":43},{"sl":51},{"sl":52},{"sl":54},{"sl":55}]}}

// JSON: { lines : [{tests : [testid1, testid2, testid3, ...]}, ...]};
clover.srcFileLines = [[], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [321, 825], [321, 825], [], [], [321, 825], [], [], [], [], [321, 825], [321, 825], [], [321, 825], [321, 825], [], []]
