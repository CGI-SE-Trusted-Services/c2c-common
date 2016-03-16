var clover = new Object();

// JSON: {classes : [{name, id, sl, el,  methods : [{sl, el}, ...]}, ...]}
clover.pageData = {"classes":[{"el":75,"id":12311,"methods":[{"el":67,"sc":2,"sl":44},{"el":72,"sc":2,"sl":69}],"name":"SignatureSpec","sl":38}]}

// JSON: {test_ID : {"methods": [ID1, ID2, ID3...], "name" : "testXXX() void"}, ...};
clover.testTargets = {"test_699":{"methods":[{"sl":44}],"name":"Verify that Signature is correctly encoded for type ecdsaNistP256Signature","pass":true,"statements":[{"sl":47},{"sl":50},{"sl":53},{"sl":57},{"sl":58},{"sl":59}]},"test_781":{"methods":[{"sl":69}],"name":"Verify toString","pass":true,"statements":[{"sl":71}]},"test_950":{"methods":[{"sl":44}],"name":"Verify that Signature is correctly encoded for type ecdsaBrainpoolP256r1Signature","pass":true,"statements":[{"sl":47},{"sl":50},{"sl":53},{"sl":57},{"sl":58},{"sl":59}]}}

// JSON: { lines : [{tests : [testid1, testid2, testid3, ...]}, ...]};
clover.srcFileLines = [[], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [699, 950], [], [], [699, 950], [], [], [699, 950], [], [], [699, 950], [], [], [], [699, 950], [699, 950], [699, 950], [], [], [], [], [], [], [], [], [], [781], [], [781], [], [], [], []]
