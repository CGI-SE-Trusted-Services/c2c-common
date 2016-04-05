var clover = new Object();

// JSON: {classes : [{name, id, sl, el,  methods : [{sl, el}, ...]}, ...]}
clover.pageData = {"classes":[{"el":88,"id":12023,"methods":[{"el":66,"sc":2,"sl":54},{"el":73,"sc":2,"sl":68},{"el":85,"sc":2,"sl":76}],"name":"ToBeSignedHashIdCrlSpec","sl":41}]}

// JSON: {test_ID : {"methods": [ID1, ID2, ID3...], "name" : "testXXX() void"}, ...};
clover.testTargets = {"test_456":{"methods":[{"sl":76}],"name":"Verify toString","pass":true,"statements":[{"sl":78}]},"test_630":{"methods":[{"sl":68}],"name":"Verify that IllegalArgumentException is thrown if not all fields are set","pass":true,"statements":[{"sl":70},{"sl":72}]},"test_704":{"methods":[{"sl":54}],"name":"Verify that constructor and getters are correct and it is correctly encoded","pass":true,"statements":[{"sl":56},{"sl":58},{"sl":59},{"sl":61},{"sl":63},{"sl":64},{"sl":65}]}}

// JSON: { lines : [{tests : [testid1, testid2, testid3, ...]}, ...]};
clover.srcFileLines = [[], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [704], [], [704], [], [704], [704], [], [704], [], [704], [704], [704], [], [], [630], [], [630], [], [630], [], [], [], [456], [], [456], [], [], [], [], [], [], [], [], [], []]
