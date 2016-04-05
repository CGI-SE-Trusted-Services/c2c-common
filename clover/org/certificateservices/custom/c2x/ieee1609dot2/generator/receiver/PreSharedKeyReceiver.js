var clover = new Object();

// JSON: {classes : [{name, id, sl, el,  methods : [{sl, el}, ...]}, ...]}
clover.pageData = {"classes":[{"el":54,"id":5428,"methods":[{"el":37,"sc":2,"sl":35},{"el":42,"sc":2,"sl":39},{"el":50,"sc":2,"sl":44}],"name":"PreSharedKeyReceiver","sl":31}]}

// JSON: {test_ID : {"methods": [ID1, ID2, ID3...], "name" : "testXXX() void"}, ...};
clover.testTargets = {"test_378":{"methods":[{"sl":35},{"sl":39},{"sl":44}],"name":"Verify that preshared key encryption works correctly","pass":true,"statements":[{"sl":36},{"sl":41},{"sl":49}]},"test_66":{"methods":[{"sl":35},{"sl":39}],"name":"Verify that buildRecieverStore generates a correct HashedId8 to Receiver Map","pass":true,"statements":[{"sl":36},{"sl":41}]}}

// JSON: { lines : [{tests : [testid1, testid2, testid3, ...]}, ...]};
clover.srcFileLines = [[], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [66, 378], [66, 378], [], [], [66, 378], [], [66, 378], [], [], [378], [], [], [], [], [378], [], [], [], [], []]
