var clover = new Object();

// JSON: {classes : [{name, id, sl, el,  methods : [{sl, el}, ...]}, ...]}
clover.pageData = {"classes":[{"el":167,"id":7910,"methods":[{"el":54,"sc":2,"sl":50},{"el":61,"sc":2,"sl":60},{"el":69,"sc":2,"sl":67},{"el":76,"sc":2,"sl":74},{"el":83,"sc":2,"sl":81},{"el":98,"sc":2,"sl":86},{"el":114,"sc":2,"sl":100},{"el":128,"sc":2,"sl":116},{"el":152,"sc":2,"sl":130},{"el":158,"sc":2,"sl":154}],"name":"RecipientInfo","sl":35}]}

// JSON: {test_ID : {"methods": [ID1, ID2, ID3...], "name" : "testXXX() void"}, ...};
clover.testTargets = {"test_134":{"methods":[{"sl":50},{"sl":116},{"sl":130}],"name":"Verify hashCode and equals","pass":true,"statements":[{"sl":51},{"sl":52},{"sl":53},{"sl":118},{"sl":119},{"sl":120},{"sl":121},{"sl":123},{"sl":127},{"sl":132},{"sl":134},{"sl":136},{"sl":138},{"sl":139},{"sl":142},{"sl":143},{"sl":144},{"sl":147},{"sl":148},{"sl":149},{"sl":151}]},"test_177":{"methods":[{"sl":67},{"sl":74},{"sl":81}],"name":"Verify constructors and getters and setters","pass":true,"statements":[{"sl":68},{"sl":75},{"sl":82}]},"test_28":{"methods":[{"sl":50},{"sl":60},{"sl":67},{"sl":74},{"sl":81},{"sl":86},{"sl":100}],"name":"Verify that signAndEncryptSecureMessage and verifyAndDecryptSecuredMessage both encrypts and signs properly","pass":true,"statements":[{"sl":51},{"sl":52},{"sl":53},{"sl":68},{"sl":75},{"sl":82},{"sl":88},{"sl":89},{"sl":90},{"sl":91},{"sl":92},{"sl":93},{"sl":102},{"sl":103},{"sl":104},{"sl":105},{"sl":106},{"sl":107},{"sl":108},{"sl":109}]},"test_3":{"methods":[{"sl":86}],"name":"Verify serialization","pass":true,"statements":[{"sl":88},{"sl":89},{"sl":90},{"sl":91},{"sl":92},{"sl":93}]},"test_339":{"methods":[{"sl":60},{"sl":67},{"sl":74},{"sl":81},{"sl":100}],"name":"Verify deserialization of EciesNistP256EncryptedKey","pass":true,"statements":[{"sl":68},{"sl":75},{"sl":82},{"sl":102},{"sl":103},{"sl":104},{"sl":105},{"sl":106},{"sl":107},{"sl":108},{"sl":109}]},"test_359":{"methods":[{"sl":50},{"sl":60},{"sl":67},{"sl":74},{"sl":81},{"sl":86},{"sl":100}],"name":"verify that encryptSecureMessage and decryptSecureMessage encrypts and decrypts correctly","pass":true,"statements":[{"sl":51},{"sl":52},{"sl":53},{"sl":68},{"sl":75},{"sl":82},{"sl":88},{"sl":89},{"sl":90},{"sl":91},{"sl":92},{"sl":93},{"sl":102},{"sl":103},{"sl":104},{"sl":105},{"sl":106},{"sl":107},{"sl":108},{"sl":109}]},"test_376":{"methods":[{"sl":154}],"name":"Verify toString","pass":true,"statements":[{"sl":156}]},"test_575":{"methods":[{"sl":50},{"sl":67}],"name":"Verify that findRecipientInfo find correct RecipientInfo","pass":true,"statements":[{"sl":51},{"sl":52},{"sl":53},{"sl":68}]},"test_585":{"methods":[{"sl":86}],"name":"Verify serialization of RecipientInfo","pass":true,"statements":[{"sl":88},{"sl":89},{"sl":90},{"sl":91},{"sl":92},{"sl":93}]},"test_861":{"methods":[{"sl":154}],"name":"Verify toString","pass":true,"statements":[{"sl":156}]},"test_913":{"methods":[{"sl":60},{"sl":100}],"name":"Verify deserialization","pass":true,"statements":[{"sl":102},{"sl":103},{"sl":104},{"sl":105},{"sl":106},{"sl":107},{"sl":108},{"sl":109}]}}

// JSON: { lines : [{tests : [testid1, testid2, testid3, ...]}, ...]};
clover.srcFileLines = [[], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [575, 134, 28, 359], [575, 134, 28, 359], [575, 134, 28, 359], [575, 134, 28, 359], [], [], [], [], [], [], [913, 339, 28, 359], [], [], [], [], [], [], [575, 339, 177, 28, 359], [575, 339, 177, 28, 359], [], [], [], [], [], [339, 177, 28, 359], [339, 177, 28, 359], [], [], [], [], [], [339, 177, 28, 359], [339, 177, 28, 359], [], [], [], [585, 3, 28, 359], [], [585, 3, 28, 359], [585, 3, 28, 359], [585, 3, 28, 359], [585, 3, 28, 359], [585, 3, 28, 359], [585, 3, 28, 359], [], [], [], [], [], [], [913, 339, 28, 359], [], [913, 339, 28, 359], [913, 339, 28, 359], [913, 339, 28, 359], [913, 339, 28, 359], [913, 339, 28, 359], [913, 339, 28, 359], [913, 339, 28, 359], [913, 339, 28, 359], [], [], [], [], [], [], [134], [], [134], [134], [134], [134], [], [134], [], [], [], [134], [], [], [134], [], [134], [], [134], [], [134], [], [134], [134], [], [], [134], [134], [134], [], [], [134], [134], [134], [], [134], [], [], [861, 376], [], [861, 376], [], [], [], [], [], [], [], [], [], [], []]
