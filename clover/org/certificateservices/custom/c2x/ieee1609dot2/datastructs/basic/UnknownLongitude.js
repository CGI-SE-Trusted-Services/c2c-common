var clover = new Object();

// JSON: {classes : [{name, id, sl, el,  methods : [{sl, el}, ...]}, ...]}
clover.pageData = {"classes":[{"el":40,"id":3411,"methods":[{"el":31,"sc":2,"sl":29},{"el":38,"sc":2,"sl":35}],"name":"UnknownLongitude","sl":22}]}

// JSON: {test_ID : {"methods": [ID1, ID2, ID3...], "name" : "testXXX() void"}, ...};
clover.testTargets = {"test_268":{"methods":[{"sl":29}],"name":"Verify that UnknownLongitude constructors sets the correct min and max values.","pass":true,"statements":[{"sl":30}]},"test_563":{"methods":[{"sl":29},{"sl":35}],"name":"Verify UnknownLongitude toString","pass":true,"statements":[{"sl":30},{"sl":37}]}}

// JSON: { lines : [{tests : [testid1, testid2, testid3, ...]}, ...]};
clover.srcFileLines = [[], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [268, 563], [268, 563], [], [], [], [], [563], [], [563], [], [], []]
