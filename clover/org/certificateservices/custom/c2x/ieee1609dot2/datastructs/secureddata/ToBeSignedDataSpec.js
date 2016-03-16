var clover = new Object();

// JSON: {classes : [{name, id, sl, el,  methods : [{sl, el}, ...]}, ...]}
clover.pageData = {"classes":[{"el":99,"id":10161,"methods":[{"el":63,"sc":2,"sl":50},{"el":71,"sc":2,"sl":65},{"el":83,"sc":2,"sl":73},{"el":96,"sc":2,"sl":86}],"name":"ToBeSignedDataSpec","sl":45}]}

// JSON: {test_ID : {"methods": [ID1, ID2, ID3...], "name" : "testXXX() void"}, ...};
clover.testTargets = {"test_259":{"methods":[{"sl":65}],"name":"Verify that encode and decode to byte array is correct","pass":true,"statements":[{"sl":67},{"sl":68},{"sl":70}]},"test_470":{"methods":[{"sl":50}],"name":"Verify that constructor and getters are correct and it is correctly encoded","pass":true,"statements":[{"sl":52},{"sl":54},{"sl":55},{"sl":57},{"sl":59},{"sl":60},{"sl":61}]},"test_550":{"methods":[{"sl":86}],"name":"Verify toString","pass":true,"statements":[{"sl":88}]},"test_658":{"methods":[{"sl":73}],"name":"Verify that IllegalArgumentException is thrown when encoding if not all required fields are set","pass":true,"statements":[{"sl":75},{"sl":77},{"sl":79},{"sl":81}]}}

// JSON: { lines : [{tests : [testid1, testid2, testid3, ...]}, ...]};
clover.srcFileLines = [[], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [470], [], [470], [], [470], [470], [], [470], [], [470], [470], [470], [], [], [], [259], [], [259], [259], [], [259], [], [], [658], [], [658], [], [658], [], [658], [], [658], [], [], [], [], [550], [], [550], [], [], [], [], [], [], [], [], [], [], []]
