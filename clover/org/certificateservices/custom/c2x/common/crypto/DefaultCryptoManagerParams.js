var clover = new Object();

// JSON: {classes : [{name, id, sl, el,  methods : [{sl, el}, ...]}, ...]}
clover.pageData = {"classes":[{"el":45,"id":2163,"methods":[{"el":33,"sc":2,"sl":30},{"el":41,"sc":2,"sl":39}],"name":"DefaultCryptoManagerParams","sl":22}]}

// JSON: {test_ID : {"methods": [ID1, ID2, ID3...], "name" : "testXXX() void"}, ...};
clover.testTargets = {"test_116":{"methods":[{"sl":30},{"sl":39}],"name":"Verify that constructor and getters and setters work","pass":true,"statements":[{"sl":31},{"sl":32},{"sl":40}]},"test_368":{"methods":[{"sl":30},{"sl":39}],"name":"Verify that certificate signature R point normalises signature r value to X only","pass":true,"statements":[{"sl":31},{"sl":32},{"sl":40}]}}

// JSON: { lines : [{tests : [testid1, testid2, testid3, ...]}, ...]};
clover.srcFileLines = [[], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [116, 368], [116, 368], [116, 368], [], [], [], [], [], [], [116, 368], [116, 368], [], [], [], [], []]
