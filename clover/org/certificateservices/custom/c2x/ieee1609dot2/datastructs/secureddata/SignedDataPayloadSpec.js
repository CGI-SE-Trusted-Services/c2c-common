var clover = new Object();

// JSON: {classes : [{name, id, sl, el,  methods : [{sl, el}, ...]}, ...]}
clover.pageData = {"classes":[{"el":102,"id":12154,"methods":[{"el":67,"sc":2,"sl":55},{"el":74,"sc":2,"sl":69},{"el":99,"sc":2,"sl":77}],"name":"SignedDataPayloadSpec","sl":45}]}

// JSON: {test_ID : {"methods": [ID1, ID2, ID3...], "name" : "testXXX() void"}, ...};
clover.testTargets = {"test_100":{"methods":[{"sl":69}],"name":"Verify that IllegalArgumentException is thrown if both data and exthash is null","pass":true,"statements":[{"sl":71},{"sl":73}]},"test_592":{"methods":[{"sl":55}],"name":"Verify that constructor and getters are correct and it is correctly encoded","pass":true,"statements":[{"sl":57},{"sl":58},{"sl":60},{"sl":62},{"sl":63},{"sl":64}]},"test_597":{"methods":[{"sl":77}],"name":"Verify toString","pass":true,"statements":[{"sl":79},{"sl":88},{"sl":96}]}}

// JSON: { lines : [{tests : [testid1, testid2, testid3, ...]}, ...]};
clover.srcFileLines = [[], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [592], [], [592], [592], [], [592], [], [592], [592], [592], [], [], [], [], [100], [], [100], [], [100], [], [], [], [597], [], [597], [], [], [], [], [], [], [], [], [597], [], [], [], [], [], [], [], [597], [], [], [], [], [], []]
