var clover = new Object();

// JSON: {classes : [{name, id, sl, el,  methods : [{sl, el}, ...]}, ...]}
clover.pageData = {"classes":[{"el":77,"id":12462,"methods":[{"el":56,"sc":2,"sl":44},{"el":67,"sc":2,"sl":58},{"el":74,"sc":2,"sl":71}],"name":"PublicEncryptionKeySpec","sl":37}]}

// JSON: {test_ID : {"methods": [ID1, ID2, ID3...], "name" : "testXXX() void"}, ...};
clover.testTargets = {"test_150":{"methods":[{"sl":44}],"name":"Verify that constructor and getters are correct and it is correctly encoded","pass":true,"statements":[{"sl":46},{"sl":48},{"sl":50},{"sl":52},{"sl":53}]},"test_663":{"methods":[{"sl":71}],"name":"Verify toString","pass":true,"statements":[{"sl":73}]},"test_69":{"methods":[{"sl":58}],"name":"Verify that IllegalArgumentException is thrown when encoding if not all fields are set","pass":true,"statements":[{"sl":60},{"sl":62},{"sl":64},{"sl":66}]}}

// JSON: { lines : [{tests : [testid1, testid2, testid3, ...]}, ...]};
clover.srcFileLines = [[], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [150], [], [150], [], [150], [], [150], [], [150], [150], [], [], [], [], [69], [], [69], [], [69], [], [69], [], [69], [], [], [], [], [663], [], [663], [], [], [], []]
