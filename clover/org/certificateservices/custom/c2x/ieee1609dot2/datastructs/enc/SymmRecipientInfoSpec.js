var clover = new Object();

// JSON: {classes : [{name, id, sl, el,  methods : [{sl, el}, ...]}, ...]}
clover.pageData = {"classes":[{"el":83,"id":12345,"methods":[{"el":63,"sc":2,"sl":51},{"el":74,"sc":2,"sl":65},{"el":80,"sc":2,"sl":77}],"name":"SymmRecipientInfoSpec","sl":42}]}

// JSON: {test_ID : {"methods": [ID1, ID2, ID3...], "name" : "testXXX() void"}, ...};
clover.testTargets = {"test_281":{"methods":[{"sl":65}],"name":"Verify that IllegalArgumentException is thrown when encoding if not all fields are set","pass":true,"statements":[{"sl":67},{"sl":69},{"sl":71},{"sl":73}]},"test_56":{"methods":[{"sl":51}],"name":"Verify that constructor and getters are correct and it is correctly encoded","pass":true,"statements":[{"sl":53},{"sl":55},{"sl":57},{"sl":59},{"sl":60}]},"test_932":{"methods":[{"sl":77}],"name":"Verify toString","pass":true,"statements":[{"sl":79}]}}

// JSON: { lines : [{tests : [testid1, testid2, testid3, ...]}, ...]};
clover.srcFileLines = [[], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [56], [], [56], [], [56], [], [56], [], [56], [56], [], [], [], [], [281], [], [281], [], [281], [], [281], [], [281], [], [], [], [932], [], [932], [], [], [], []]
