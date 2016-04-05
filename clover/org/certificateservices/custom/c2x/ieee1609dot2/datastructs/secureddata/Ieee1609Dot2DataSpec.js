var clover = new Object();

// JSON: {classes : [{name, id, sl, el,  methods : [{sl, el}, ...]}, ...]}
clover.pageData = {"classes":[{"el":140,"id":10235,"methods":[{"el":64,"sc":2,"sl":47},{"el":72,"sc":2,"sl":66},{"el":126,"sc":2,"sl":77},{"el":137,"sc":2,"sl":129}],"name":"Ieee1609Dot2DataSpec","sl":42}]}

// JSON: {test_ID : {"methods": [ID1, ID2, ID3...], "name" : "testXXX() void"}, ...};
clover.testTargets = {"test_331":{"methods":[{"sl":47}],"name":"Verify that constructor and getters are correct and it is correctly encoded","pass":true,"statements":[{"sl":49},{"sl":51},{"sl":52},{"sl":54},{"sl":56},{"sl":57},{"sl":58},{"sl":60},{"sl":62}]},"test_67":{"methods":[{"sl":66}],"name":"Verify that IllegalArgumentException is thrown when encoding if not all required fields are set","pass":true,"statements":[{"sl":68},{"sl":70}]},"test_908":{"methods":[{"sl":129}],"name":"Verify toString","pass":true,"statements":[{"sl":131}]},"test_949":{"methods":[{"sl":77}],"name":"Verify that reference structure from D.5.2.2 of P1909.2_D12 is parsed and regenerated correctly","pass":true,"statements":[{"sl":79},{"sl":81},{"sl":125}]}}

// JSON: { lines : [{tests : [testid1, testid2, testid3, ...]}, ...]};
clover.srcFileLines = [[], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [331], [], [331], [], [331], [331], [], [331], [], [331], [331], [331], [], [331], [], [331], [], [], [], [67], [], [67], [], [67], [], [], [], [], [], [], [949], [], [949], [], [949], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [949], [], [], [], [908], [], [908], [], [], [], [], [], [], [], [], []]
