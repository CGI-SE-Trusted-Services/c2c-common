var clover = new Object();

// JSON: {classes : [{name, id, sl, el,  methods : [{sl, el}, ...]}, ...]}
clover.pageData = {"classes":[{"el":64,"id":12385,"methods":[{"el":41,"sc":2,"sl":25},{"el":48,"sc":2,"sl":43},{"el":56,"sc":2,"sl":50},{"el":61,"sc":2,"sl":58}],"name":"COERBooleanSpec","sl":21}]}

// JSON: {test_ID : {"methods": [ID1, ID2, ID3...], "name" : "testXXX() void"}, ...};
clover.testTargets = {"test_247":{"methods":[{"sl":50}],"name":"Verify equals and hashcode","pass":true,"statements":[{"sl":52},{"sl":53},{"sl":54},{"sl":55}]},"test_291":{"methods":[{"sl":43}],"name":"Verify that IOException is thrown when deserializing invalid COER boolean value","pass":true,"statements":[{"sl":45},{"sl":47}]},"test_827":{"methods":[{"sl":25}],"name":"Verify that COERBoolean with value true returns 00 encoded and encoded 00 generates a true value","pass":true,"statements":[{"sl":28},{"sl":30},{"sl":33},{"sl":35}]},"test_840":{"methods":[{"sl":58}],"name":"Verify toString","pass":true,"statements":[{"sl":60}]},"test_883":{"methods":[{"sl":25}],"name":"Verify that COERBoolean with value false returns ff encoded and encoded ff generates a false value","pass":true,"statements":[{"sl":28},{"sl":30},{"sl":33},{"sl":35}]}}

// JSON: { lines : [{tests : [testid1, testid2, testid3, ...]}, ...]};
clover.srcFileLines = [[], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [827, 883], [], [], [827, 883], [], [827, 883], [], [], [827, 883], [], [827, 883], [], [], [], [], [], [], [], [291], [], [291], [], [291], [], [], [247], [], [247], [247], [247], [247], [], [], [840], [], [840], [], [], [], []]
