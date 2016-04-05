var clover = new Object();

// JSON: {classes : [{name, id, sl, el,  methods : [{sl, el}, ...]}, ...]}
clover.pageData = {"classes":[{"el":60,"id":5447,"methods":[{"el":41,"sc":2,"sl":39},{"el":46,"sc":2,"sl":43},{"el":58,"sc":2,"sl":48}],"name":"SymmetricKeyReceiver","sl":35}]}

// JSON: {test_ID : {"methods": [ID1, ID2, ID3...], "name" : "testXXX() void"}, ...};
clover.testTargets = {"test_354":{"methods":[{"sl":39},{"sl":43},{"sl":48}],"name":"Verify that symmetric key envelope encryption works correctly","pass":true,"statements":[{"sl":40},{"sl":45},{"sl":53},{"sl":55},{"sl":56},{"sl":57}]},"test_66":{"methods":[{"sl":39},{"sl":43}],"name":"Verify that buildRecieverStore generates a correct HashedId8 to Receiver Map","pass":true,"statements":[{"sl":40},{"sl":45}]}}

// JSON: { lines : [{tests : [testid1, testid2, testid3, ...]}, ...]};
clover.srcFileLines = [[], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [66, 354], [66, 354], [], [], [66, 354], [], [66, 354], [], [], [354], [], [], [], [], [354], [], [354], [354], [354], [], [], []]
