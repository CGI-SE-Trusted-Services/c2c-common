var clover = new Object();

// JSON: {classes : [{name, id, sl, el,  methods : [{sl, el}, ...]}, ...]}
clover.pageData = {"classes":[{"el":66,"id":9106,"methods":[{"el":47,"sc":2,"sl":36},{"el":58,"sc":2,"sl":49},{"el":63,"sc":2,"sl":60}],"name":"CountryAndRegionsSpec","sl":32}]}

// JSON: {test_ID : {"methods": [ID1, ID2, ID3...], "name" : "testXXX() void"}, ...};
clover.testTargets = {"test_202":{"methods":[{"sl":60}],"name":"Verify toString","pass":true,"statements":[{"sl":62}]},"test_429":{"methods":[{"sl":36}],"name":"Verify that constructor and getters are correct and it is correctly encoded","pass":true,"statements":[{"sl":38},{"sl":40},{"sl":42},{"sl":44},{"sl":45}]},"test_77":{"methods":[{"sl":49}],"name":"Verify that all fields must be set or IllegalArgumentException is thrown when encoding","pass":true,"statements":[{"sl":51},{"sl":53},{"sl":55},{"sl":57}]}}

// JSON: { lines : [{tests : [testid1, testid2, testid3, ...]}, ...]};
clover.srcFileLines = [[], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [429], [], [429], [], [429], [], [429], [], [429], [429], [], [], [], [77], [], [77], [], [77], [], [77], [], [77], [], [], [202], [], [202], [], [], [], []]
