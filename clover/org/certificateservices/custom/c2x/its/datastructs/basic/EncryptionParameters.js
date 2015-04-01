var clover = new Object();

// JSON: {classes : [{name, id, sl, el,  methods : [{sl, el}, ...]}, ...]}
clover.pageData = {"classes":[{"el":92,"id":879,"methods":[{"el":55,"sc":2,"sl":45},{"el":60,"sc":2,"sl":60},{"el":64,"sc":2,"sl":62},{"el":68,"sc":2,"sl":66},{"el":74,"sc":2,"sl":70},{"el":84,"sc":2,"sl":76},{"el":90,"sc":2,"sl":86}],"name":"EncryptionParameters","sl":34}]}

// JSON: {test_ID : {"methods": [ID1, ID2, ID3...], "name" : "testXXX() void"}, ...};
clover.testTargets = {"test_152":{"methods":[{"sl":45},{"sl":60},{"sl":66},{"sl":70},{"sl":76}],"name":"Verify that signAndEncryptSecureMessage and verifyAndDecryptSecuredMessage both encrypts and signs properly","pass":true,"statements":[{"sl":46},{"sl":49},{"sl":53},{"sl":54},{"sl":67},{"sl":72},{"sl":73},{"sl":78},{"sl":79},{"sl":82},{"sl":83}]},"test_154":{"methods":[{"sl":86}],"name":"Verify toString","pass":true,"statements":[{"sl":88}]},"test_229":{"methods":[{"sl":45},{"sl":70}],"name":"Verify serialization of EncryptionParameters","pass":true,"statements":[{"sl":46},{"sl":49},{"sl":53},{"sl":54},{"sl":72},{"sl":73}]},"test_266":{"methods":[{"sl":45},{"sl":86}],"name":"Verify toString","pass":true,"statements":[{"sl":46},{"sl":49},{"sl":53},{"sl":54},{"sl":88}]},"test_280":{"methods":[{"sl":60},{"sl":62},{"sl":66},{"sl":76}],"name":"Verify deserialization of EncryptionParameters","pass":true,"statements":[{"sl":63},{"sl":67},{"sl":78},{"sl":79},{"sl":82},{"sl":83}]},"test_333":{"methods":[{"sl":45},{"sl":62},{"sl":66}],"name":"Verify constructors and getters and setters","pass":true,"statements":[{"sl":46},{"sl":47},{"sl":49},{"sl":50},{"sl":53},{"sl":54},{"sl":63},{"sl":67}]},"test_39":{"methods":[{"sl":70}],"name":"Verify serialization","pass":true,"statements":[{"sl":72},{"sl":73}]},"test_64":{"methods":[{"sl":45},{"sl":60},{"sl":66},{"sl":70},{"sl":76}],"name":"verify that encryptSecureMessage and decryptSecureMessage encrypts and decrypts correctly","pass":true,"statements":[{"sl":46},{"sl":49},{"sl":53},{"sl":54},{"sl":67},{"sl":72},{"sl":73},{"sl":78},{"sl":79},{"sl":82},{"sl":83}]},"test_75":{"methods":[{"sl":60},{"sl":76}],"name":"Verify deserialization","pass":true,"statements":[{"sl":78},{"sl":79},{"sl":82},{"sl":83}]}}

// JSON: { lines : [{tests : [testid1, testid2, testid3, ...]}, ...]};
clover.srcFileLines = [[], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [229, 152, 333, 266, 64], [229, 152, 333, 266, 64], [333], [], [229, 152, 333, 266, 64], [333], [], [], [229, 152, 333, 266, 64], [229, 152, 333, 266, 64], [], [], [], [], [], [152, 75, 280, 64], [], [333, 280], [333, 280], [], [], [152, 333, 280, 64], [152, 333, 280, 64], [], [], [39, 229, 152, 64], [], [39, 229, 152, 64], [39, 229, 152, 64], [], [], [152, 75, 280, 64], [], [152, 75, 280, 64], [152, 75, 280, 64], [], [], [152, 75, 280, 64], [152, 75, 280, 64], [], [], [154, 266], [], [154, 266], [], [], [], []]
