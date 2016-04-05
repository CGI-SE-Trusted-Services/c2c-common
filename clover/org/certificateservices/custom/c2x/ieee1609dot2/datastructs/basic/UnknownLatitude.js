var clover = new Object();

// JSON: {classes : [{name, id, sl, el,  methods : [{sl, el}, ...]}, ...]}
clover.pageData = {"classes":[{"el":42,"id":3407,"methods":[{"el":31,"sc":2,"sl":29},{"el":38,"sc":2,"sl":35}],"name":"UnknownLatitude","sl":22}]}

// JSON: {test_ID : {"methods": [ID1, ID2, ID3...], "name" : "testXXX() void"}, ...};
clover.testTargets = {"test_416":{"methods":[{"sl":29},{"sl":35}],"name":"Verify UnknownLatitude toString","pass":true,"statements":[{"sl":30},{"sl":37}]},"test_567":{"methods":[{"sl":29}],"name":"Verify that UnknownLatitude constructors sets the correct min and max values.","pass":true,"statements":[{"sl":30}]}}

// JSON: { lines : [{tests : [testid1, testid2, testid3, ...]}, ...]};
clover.srcFileLines = [[], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [567, 416], [567, 416], [], [], [], [], [416], [], [416], [], [], [], [], []]
