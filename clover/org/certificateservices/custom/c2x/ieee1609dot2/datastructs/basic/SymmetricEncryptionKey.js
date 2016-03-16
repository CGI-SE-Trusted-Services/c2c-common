var clover = new Object();

// JSON: {classes : [{name, id, sl, el,  methods : [{sl, el}, ...]}, ...]}
clover.pageData = {"classes":[{"el":76,"id":3141,"methods":[{"el":55,"sc":2,"sl":53},{"el":62,"sc":2,"sl":60},{"el":69,"sc":2,"sl":67},{"el":74,"sc":2,"sl":71}],"name":"SymmetricEncryptionKey","sl":34},{"el":48,"id":3141,"methods":[{"el":46,"sc":3,"sl":43}],"name":"SymmetricEncryptionKey.SymmetricEncryptionKeyChoices","sl":40}]}

// JSON: {test_ID : {"methods": [ID1, ID2, ID3...], "name" : "testXXX() void"}, ...};
clover.testTargets = {"test_175":{"methods":[{"sl":43},{"sl":60}],"name":"Verify that EncryptionKey is correctly encoded for type symmetric","pass":true,"statements":[{"sl":45},{"sl":61}]},"test_19":{"methods":[{"sl":71}],"name":"Verify toString","pass":true,"statements":[{"sl":73}]},"test_296":{"methods":[{"sl":71}],"name":"Verify toString","pass":true,"statements":[{"sl":73}]},"test_488":{"methods":[{"sl":43},{"sl":53},{"sl":60},{"sl":67}],"name":"Verify that SymmetricEncryptionKey is correctly encoded for type aes128Ccm","pass":true,"statements":[{"sl":45},{"sl":54},{"sl":61},{"sl":68}]},"test_630":{"methods":[{"sl":53},{"sl":71}],"name":"Verify toString","pass":true,"statements":[{"sl":54},{"sl":73}]},"test_662":{"methods":[{"sl":43},{"sl":60}],"name":"Verify that constructor and getters are correct and it is correctly encoded","pass":true,"statements":[{"sl":45},{"sl":61}]}}

// JSON: { lines : [{tests : [testid1, testid2, testid3, ...]}, ...]};
clover.srcFileLines = [[], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [662, 175, 488], [], [662, 175, 488], [], [], [], [], [], [], [], [630, 488], [630, 488], [], [], [], [], [], [662, 175, 488], [662, 175, 488], [], [], [], [], [], [488], [488], [], [], [296, 19, 630], [], [296, 19, 630], [], [], []]
