var clover = new Object();

// JSON: {classes : [{name, id, sl, el,  methods : [{sl, el}, ...]}, ...]}
clover.pageData = {"classes":[{"el":44,"id":4103,"methods":[{"el":37,"sc":2,"sl":35},{"el":43,"sc":2,"sl":40}],"name":"CrlPsid","sl":25}]}

// JSON: {test_ID : {"methods": [ID1, ID2, ID3...], "name" : "testXXX() void"}, ...};
clover.testTargets = {"test_212":{"methods":[{"sl":35},{"sl":40}],"name":"Verify toString","pass":true,"statements":[{"sl":36},{"sl":42}]},"test_381":{"methods":[{"sl":40}],"name":"Verify toString","pass":true,"statements":[{"sl":42}]},"test_686":{"methods":[{"sl":35}],"name":"Verify that signed SecuredCrl with signed data is generated correctly","pass":true,"statements":[{"sl":36}]},"test_837":{"methods":[{"sl":35}],"name":"Verify that constructor and getters are correct and it is correctly encoded","pass":true,"statements":[{"sl":36}]}}

// JSON: { lines : [{tests : [testid1, testid2, testid3, ...]}, ...]};
clover.srcFileLines = [[], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [686, 837, 212], [686, 837, 212], [], [], [], [381, 212], [], [381, 212], [], []]
