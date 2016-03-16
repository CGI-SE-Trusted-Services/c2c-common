var clover = new Object();

// JSON: {classes : [{name, id, sl, el,  methods : [{sl, el}, ...]}, ...]}
clover.pageData = {"classes":[{"el":75,"id":12842,"methods":[{"el":43,"sc":2,"sl":38},{"el":50,"sc":2,"sl":45},{"el":55,"sc":2,"sl":52},{"el":62,"sc":2,"sl":57},{"el":74,"sc":2,"sl":64}],"name":"HashedIdSpec","sl":31}]}

// JSON: {test_ID : {"methods": [ID1, ID2, ID3...], "name" : "testXXX() void"}, ...};
clover.testTargets = {"test_127":{"methods":[{"sl":57}],"name":"Verify deserialization of a hash value","pass":true,"statements":[{"sl":59},{"sl":61}]},"test_171":{"methods":[{"sl":52}],"name":"Verify serialization of a hash value","pass":true,"statements":[{"sl":54}]},"test_327":{"methods":[{"sl":38}],"name":"Verify the correct octet length of the HashedId3","pass":true,"statements":[{"sl":40},{"sl":41}]},"test_46":{"methods":[{"sl":64}],"name":"Verify hashCode and equals","pass":true,"statements":[{"sl":66},{"sl":67},{"sl":68},{"sl":70},{"sl":71},{"sl":72},{"sl":73}]},"test_841":{"methods":[{"sl":45}],"name":"Verify IllegalArgumentException is thrown if to small hash value is given.","pass":true,"statements":[{"sl":47},{"sl":49}]}}

// JSON: { lines : [{tests : [testid1, testid2, testid3, ...]}, ...]};
clover.srcFileLines = [[], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [327], [], [327], [327], [], [], [], [841], [], [841], [], [841], [], [], [171], [], [171], [], [], [127], [], [127], [], [127], [], [], [46], [], [46], [46], [46], [], [46], [46], [46], [46], [], []]
