var clover = new Object();

// JSON: {classes : [{name, id, sl, el,  methods : [{sl, el}, ...]}, ...]}
clover.pageData = {"classes":[{"el":56,"id":2601,"methods":[{"el":37,"sc":2,"sl":34},{"el":47,"sc":2,"sl":44},{"el":52,"sc":2,"sl":49}],"name":"KnownLongitude","sl":27}]}

// JSON: {test_ID : {"methods": [ID1, ID2, ID3...], "name" : "testXXX() void"}, ...};
clover.testTargets = {"test_11":{"methods":[{"sl":34},{"sl":44}],"name":"Verify that KnownLongitude constructors sets the correct min and max values.","pass":true,"statements":[{"sl":35},{"sl":36},{"sl":45},{"sl":46}]},"test_890":{"methods":[{"sl":44},{"sl":49}],"name":"Verify KnownLongitude toString","pass":true,"statements":[{"sl":45},{"sl":46},{"sl":51}]}}

// JSON: { lines : [{tests : [testid1, testid2, testid3, ...]}, ...]};
clover.srcFileLines = [[], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [11], [11], [11], [], [], [], [], [], [], [], [11, 890], [11, 890], [11, 890], [], [], [890], [], [890], [], [], [], [], []]
