var clover = new Object();

// JSON: {classes : [{name, id, sl, el,  methods : [{sl, el}, ...]}, ...]}
clover.pageData = {"classes":[{"el":43,"id":9007,"methods":[{"el":27,"sc":2,"sl":23},{"el":35,"sc":2,"sl":29},{"el":40,"sc":2,"sl":37}],"name":"COERNullSpec","sl":21}]}

// JSON: {test_ID : {"methods": [ID1, ID2, ID3...], "name" : "testXXX() void"}, ...};
clover.testTargets = {"test_23":{"methods":[{"sl":23}],"name":"Verify that COERNull with value #value returns #encoded encoded and encoded #encoded generates a #value value","pass":true,"statements":[{"sl":25},{"sl":26}]},"test_548":{"methods":[{"sl":29}],"name":"Verify equals and hashcode","pass":true,"statements":[{"sl":31},{"sl":32},{"sl":33},{"sl":34}]},"test_632":{"methods":[{"sl":37}],"name":"Verify toString","pass":true,"statements":[{"sl":39}]}}

// JSON: { lines : [{tests : [testid1, testid2, testid3, ...]}, ...]};
clover.srcFileLines = [[], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [23], [], [23], [23], [], [], [548], [], [548], [548], [548], [548], [], [], [632], [], [632], [], [], [], []]
