var clover = new Object();

// JSON: {classes : [{name, id, sl, el,  methods : [{sl, el}, ...]}, ...]}
clover.pageData = {"classes":[{"el":55,"id":2708,"methods":[{"el":37,"sc":2,"sl":34},{"el":46,"sc":2,"sl":43},{"el":51,"sc":2,"sl":48}],"name":"KnownLatitude","sl":27}]}

// JSON: {test_ID : {"methods": [ID1, ID2, ID3...], "name" : "testXXX() void"}, ...};
clover.testTargets = {"test_676":{"methods":[{"sl":43},{"sl":48}],"name":"Verify KnownLatitude toString","pass":true,"statements":[{"sl":44},{"sl":45},{"sl":50}]},"test_793":{"methods":[{"sl":34},{"sl":43}],"name":"Verify that KnownLatitude constructors sets the correct min and max values.","pass":true,"statements":[{"sl":35},{"sl":36},{"sl":44},{"sl":45}]}}

// JSON: { lines : [{tests : [testid1, testid2, testid3, ...]}, ...]};
clover.srcFileLines = [[], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [793], [793], [793], [], [], [], [], [], [], [676, 793], [676, 793], [676, 793], [], [], [676], [], [676], [], [], [], [], []]
