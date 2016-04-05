var clover = new Object();

// JSON: {classes : [{name, id, sl, el,  methods : [{sl, el}, ...]}, ...]}
clover.pageData = {"classes":[{"el":41,"id":12168,"methods":[{"el":33,"sc":2,"sl":28},{"el":39,"sc":2,"sl":35}],"name":"TestCOEREnumeration","sl":21}]}

// JSON: {test_ID : {"methods": [ID1, ID2, ID3...], "name" : "testXXX() void"}, ...};
clover.testTargets = {"test_440":{"methods":[{"sl":35}],"name":"Verify that COERChoice is encoded and is decoded back to the same values[0]","pass":true,"statements":[{"sl":37},{"sl":38}]},"test_638":{"methods":[{"sl":35}],"name":"Verify that COERChoice is encoded and is decoded back to the same values[1]","pass":true,"statements":[{"sl":37},{"sl":38}]},"test_772":{"methods":[{"sl":35}],"name":"Verify that COERChoice is encoded and is decoded back to the same values[2]","pass":true,"statements":[{"sl":37},{"sl":38}]}}

// JSON: { lines : [{tests : [testid1, testid2, testid3, ...]}, ...]};
clover.srcFileLines = [[], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [772, 440, 638], [], [772, 440, 638], [772, 440, 638], [], [], []]
