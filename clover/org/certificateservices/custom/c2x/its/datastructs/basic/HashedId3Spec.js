var clover = new Object();

// JSON: {classes : [{name, id, sl, el,  methods : [{sl, el}, ...]}, ...]}
clover.pageData = {"classes":[{"el":45,"id":5598,"methods":[{"el":38,"sc":2,"sl":34},{"el":43,"sc":2,"sl":40}],"name":"HashedId3Spec","sl":31}]}

// JSON: {test_ID : {"methods": [ID1, ID2, ID3...], "name" : "testXXX() void"}, ...};
clover.testTargets = {"test_137":{"methods":[{"sl":34}],"name":"Verify the correct octet length of the HashedId3","pass":true,"statements":[{"sl":36}]},"test_141":{"methods":[{"sl":40}],"name":"Verify toString","pass":true,"statements":[{"sl":42}]}}

// JSON: { lines : [{tests : [testid1, testid2, testid3, ...]}, ...]};
clover.srcFileLines = [[], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [137], [], [137], [], [], [], [141], [], [141], [], [], []]
