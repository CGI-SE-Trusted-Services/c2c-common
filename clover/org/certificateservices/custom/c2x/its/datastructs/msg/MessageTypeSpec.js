var clover = new Object();

// JSON: {classes : [{name, id, sl, el,  methods : [{sl, el}, ...]}, ...]}
clover.pageData = {"classes":[{"el":54,"id":4017,"methods":[{"el":41,"sc":2,"sl":30},{"el":52,"sc":2,"sl":43}],"name":"MessageTypeSpec","sl":28}]}

// JSON: {test_ID : {"methods": [ID1, ID2, ID3...], "name" : "testXXX() void"}, ...};
clover.testTargets = {"test_100":{"methods":[{"sl":43}],"name":"Verify that SecurityProfile.getByValue returns CAM for 2","pass":true,"statements":[{"sl":46}]},"test_30":{"methods":[{"sl":30}],"name":"Verify that CAM has value 2 and security profile","pass":true,"statements":[{"sl":33},{"sl":34}]},"test_335":{"methods":[{"sl":43}],"name":"Verify that SecurityProfile.getByValue returns DENM for 1","pass":true,"statements":[{"sl":46}]},"test_65":{"methods":[{"sl":30}],"name":"Verify that DENM has value 1 and security profile","pass":true,"statements":[{"sl":33},{"sl":34}]}}

// JSON: { lines : [{tests : [testid1, testid2, testid3, ...]}, ...]};
clover.srcFileLines = [[], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [30, 65], [], [], [30, 65], [30, 65], [], [], [], [], [], [], [], [], [335, 100], [], [], [335, 100], [], [], [], [], [], [], [], []]
