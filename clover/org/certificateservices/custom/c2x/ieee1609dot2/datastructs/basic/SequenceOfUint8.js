var clover = new Object();

// JSON: {classes : [{name, id, sl, el,  methods : [{sl, el}, ...]}, ...]}
clover.pageData = {"classes":[{"el":66,"id":3146,"methods":[{"el":35,"sc":2,"sl":33},{"el":42,"sc":2,"sl":40},{"el":49,"sc":2,"sl":47},{"el":64,"sc":2,"sl":51}],"name":"SequenceOfUint8","sl":26}]}

// JSON: {test_ID : {"methods": [ID1, ID2, ID3...], "name" : "testXXX() void"}, ...};
clover.testTargets = {"test_153":{"methods":[{"sl":33},{"sl":40},{"sl":47}],"name":"Verify that SequenceOfUint8 is initialized properly","pass":true,"statements":[{"sl":34},{"sl":41},{"sl":48}]},"test_256":{"methods":[{"sl":33}],"name":"Verify that all fields must be set or IllegalArgumentException is thrown when encoding","pass":true,"statements":[{"sl":34}]},"test_749":{"methods":[{"sl":33}],"name":"Verify that constructor and getters are correct and it is correctly encoded","pass":true,"statements":[{"sl":34}]},"test_841":{"methods":[{"sl":33},{"sl":40},{"sl":51}],"name":"Verify toString","pass":true,"statements":[{"sl":34},{"sl":41},{"sl":53},{"sl":54},{"sl":55},{"sl":56},{"sl":58},{"sl":59},{"sl":62},{"sl":63}]},"test_949":{"methods":[{"sl":33}],"name":"Verify that reference structure from D.5.2.2 of P1909.2_D12 is parsed and regenerated correctly","pass":true,"statements":[{"sl":34}]},"test_992":{"methods":[{"sl":33}],"name":"Verify toString","pass":true,"statements":[{"sl":34}]}}

// JSON: { lines : [{tests : [testid1, testid2, testid3, ...]}, ...]};
clover.srcFileLines = [[], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [256, 841, 153, 992, 749, 949], [256, 841, 153, 992, 749, 949], [], [], [], [], [], [841, 153], [841, 153], [], [], [], [], [], [153], [153], [], [], [841], [], [841], [841], [841], [841], [], [841], [841], [], [], [841], [841], [], [], []]
