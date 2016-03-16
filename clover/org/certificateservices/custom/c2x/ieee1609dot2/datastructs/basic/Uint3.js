var clover = new Object();

// JSON: {classes : [{name, id, sl, el,  methods : [{sl, el}, ...]}, ...]}
clover.pageData = {"classes":[{"el":47,"id":3247,"methods":[{"el":32,"sc":2,"sl":30},{"el":39,"sc":2,"sl":37},{"el":44,"sc":2,"sl":41}],"name":"Uint3","sl":23}]}

// JSON: {test_ID : {"methods": [ID1, ID2, ID3...], "name" : "testXXX() void"}, ...};
clover.testTargets = {"test_157":{"methods":[{"sl":30},{"sl":37}],"name":"Verify that SequenceOfUint3 is initialized properly","pass":true,"statements":[{"sl":31},{"sl":38}]},"test_31":{"methods":[{"sl":37},{"sl":41}],"name":"Verify toString","pass":true,"statements":[{"sl":38},{"sl":43}]},"test_914":{"methods":[{"sl":30},{"sl":37}],"name":"Verify toString","pass":true,"statements":[{"sl":31},{"sl":38}]},"test_956":{"methods":[{"sl":30},{"sl":37}],"name":"Verify that Uint3 has min value 0 and 7","pass":true,"statements":[{"sl":31},{"sl":38}]}}

// JSON: { lines : [{tests : [testid1, testid2, testid3, ...]}, ...]};
clover.srcFileLines = [[], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [956, 157, 914], [956, 157, 914], [], [], [], [], [], [956, 157, 914, 31], [956, 157, 914, 31], [], [], [31], [], [31], [], [], [], []]
