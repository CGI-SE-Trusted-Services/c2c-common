var clover = new Object();

// JSON: {classes : [{name, id, sl, el,  methods : [{sl, el}, ...]}, ...]}
clover.pageData = {"classes":[{"el":66,"id":2999,"methods":[{"el":35,"sc":2,"sl":33},{"el":42,"sc":2,"sl":40},{"el":49,"sc":2,"sl":47},{"el":65,"sc":2,"sl":52}],"name":"SequenceOfPsid","sl":26}]}

// JSON: {test_ID : {"methods": [ID1, ID2, ID3...], "name" : "testXXX() void"}, ...};
clover.testTargets = {"test_375":{"methods":[{"sl":33},{"sl":47},{"sl":52}],"name":"Verify toString","pass":true,"statements":[{"sl":34},{"sl":48},{"sl":54},{"sl":55},{"sl":56},{"sl":57},{"sl":59},{"sl":60},{"sl":63},{"sl":64}]},"test_829":{"methods":[{"sl":33},{"sl":40},{"sl":47}],"name":"Verify that SequenceOfPsid is initialized properly","pass":true,"statements":[{"sl":34},{"sl":41},{"sl":48}]}}

// JSON: { lines : [{tests : [testid1, testid2, testid3, ...]}, ...]};
clover.srcFileLines = [[], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [375, 829], [375, 829], [], [], [], [], [], [829], [829], [], [], [], [], [], [375, 829], [375, 829], [], [], [], [375], [], [375], [375], [375], [375], [], [375], [375], [], [], [375], [375], [], []]
