var clover = new Object();

// JSON: {classes : [{name, id, sl, el,  methods : [{sl, el}, ...]}, ...]}
clover.pageData = {"classes":[{"el":118,"id":3770,"methods":[{"el":48,"sc":2,"sl":45},{"el":61,"sc":2,"sl":53},{"el":69,"sc":2,"sl":67},{"el":77,"sc":2,"sl":75},{"el":85,"sc":2,"sl":83},{"el":93,"sc":2,"sl":91},{"el":101,"sc":2,"sl":99},{"el":109,"sc":2,"sl":103},{"el":116,"sc":2,"sl":112}],"name":"GroupCrlEntry","sl":32}]}

// JSON: {test_ID : {"methods": [ID1, ID2, ID3...], "name" : "testXXX() void"}, ...};
clover.testTargets = {"test_183":{"methods":[{"sl":53},{"sl":67},{"sl":75},{"sl":83},{"sl":91},{"sl":99},{"sl":103},{"sl":112}],"name":"Verify toString","pass":true,"statements":[{"sl":54},{"sl":55},{"sl":56},{"sl":57},{"sl":58},{"sl":59},{"sl":60},{"sl":68},{"sl":76},{"sl":84},{"sl":92},{"sl":100},{"sl":104},{"sl":105},{"sl":106},{"sl":107},{"sl":108},{"sl":114}]},"test_26":{"methods":[{"sl":45},{"sl":67},{"sl":75},{"sl":83},{"sl":91},{"sl":99},{"sl":103},{"sl":112}],"name":"Verify toString","pass":true,"statements":[{"sl":46},{"sl":47},{"sl":68},{"sl":76},{"sl":84},{"sl":92},{"sl":100},{"sl":104},{"sl":105},{"sl":106},{"sl":107},{"sl":108},{"sl":114}]},"test_274":{"methods":[{"sl":45},{"sl":103}],"name":"Verify that SequenceOfGroupCrlEntry is initialized properly","pass":true,"statements":[{"sl":46},{"sl":47},{"sl":104},{"sl":105},{"sl":106},{"sl":107},{"sl":108}]},"test_308":{"methods":[{"sl":45},{"sl":103}],"name":"Verify that CrlContentsType is correctly encoded for type fullLinkedCrl","pass":true,"statements":[{"sl":46},{"sl":47},{"sl":104},{"sl":105},{"sl":106},{"sl":107},{"sl":108}]},"test_333":{"methods":[{"sl":45},{"sl":103}],"name":"Verify that constructor and getters are correct and it is correctly encoded","pass":true,"statements":[{"sl":46},{"sl":47},{"sl":104},{"sl":105},{"sl":106},{"sl":107},{"sl":108}]},"test_368":{"methods":[{"sl":45},{"sl":103}],"name":"Verify that IllegalArgumentException is thrown if both individual and groups are null","pass":true,"statements":[{"sl":46},{"sl":47},{"sl":104},{"sl":105},{"sl":106},{"sl":107},{"sl":108}]},"test_477":{"methods":[{"sl":45},{"sl":53},{"sl":67},{"sl":75},{"sl":83},{"sl":91},{"sl":99},{"sl":103}],"name":"Verify that constructor and getters are correct and it is correctly encoded","pass":true,"statements":[{"sl":46},{"sl":47},{"sl":54},{"sl":55},{"sl":56},{"sl":57},{"sl":58},{"sl":59},{"sl":60},{"sl":68},{"sl":76},{"sl":84},{"sl":92},{"sl":100},{"sl":104},{"sl":105},{"sl":106},{"sl":107},{"sl":108}]},"test_65":{"methods":[{"sl":45},{"sl":103}],"name":"Verify that constructor and getters are correct and it is correctly encoded","pass":true,"statements":[{"sl":46},{"sl":47},{"sl":104},{"sl":105},{"sl":106},{"sl":107},{"sl":108}]},"test_686":{"methods":[{"sl":45},{"sl":103}],"name":"Verify that signed SecuredCrl with signed data is generated correctly","pass":true,"statements":[{"sl":46},{"sl":47},{"sl":104},{"sl":105},{"sl":106},{"sl":107},{"sl":108}]},"test_745":{"methods":[{"sl":53},{"sl":103}],"name":"Verify that IllegalArgumentException is thrown when encoding if not all fields are set","pass":true,"statements":[{"sl":54},{"sl":55},{"sl":56},{"sl":57},{"sl":58},{"sl":59},{"sl":60},{"sl":104},{"sl":105},{"sl":106},{"sl":107},{"sl":108}]},"test_885":{"methods":[{"sl":45},{"sl":67},{"sl":75},{"sl":83},{"sl":91},{"sl":99},{"sl":103},{"sl":112}],"name":"Verify toString","pass":true,"statements":[{"sl":46},{"sl":47},{"sl":68},{"sl":76},{"sl":84},{"sl":92},{"sl":100},{"sl":104},{"sl":105},{"sl":106},{"sl":107},{"sl":108},{"sl":114}]},"test_889":{"methods":[{"sl":45},{"sl":103}],"name":"Verify that CrlContentsType is correctly encoded for type deltaLinkedCrl","pass":true,"statements":[{"sl":46},{"sl":47},{"sl":104},{"sl":105},{"sl":106},{"sl":107},{"sl":108}]}}

// JSON: { lines : [{tests : [testid1, testid2, testid3, ...]}, ...]};
clover.srcFileLines = [[], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [686, 333, 477, 885, 889, 308, 274, 368, 26, 65], [686, 333, 477, 885, 889, 308, 274, 368, 26, 65], [686, 333, 477, 885, 889, 308, 274, 368, 26, 65], [], [], [], [], [], [477, 183, 745], [477, 183, 745], [477, 183, 745], [477, 183, 745], [477, 183, 745], [477, 183, 745], [477, 183, 745], [477, 183, 745], [], [], [], [], [], [], [477, 885, 26, 183], [477, 885, 26, 183], [], [], [], [], [], [], [477, 885, 26, 183], [477, 885, 26, 183], [], [], [], [], [], [], [477, 885, 26, 183], [477, 885, 26, 183], [], [], [], [], [], [], [477, 885, 26, 183], [477, 885, 26, 183], [], [], [], [], [], [], [477, 885, 26, 183], [477, 885, 26, 183], [], [], [686, 333, 477, 885, 889, 308, 274, 368, 26, 65, 183, 745], [686, 333, 477, 885, 889, 308, 274, 368, 26, 65, 183, 745], [686, 333, 477, 885, 889, 308, 274, 368, 26, 65, 183, 745], [686, 333, 477, 885, 889, 308, 274, 368, 26, 65, 183, 745], [686, 333, 477, 885, 889, 308, 274, 368, 26, 65, 183, 745], [686, 333, 477, 885, 889, 308, 274, 368, 26, 65, 183, 745], [], [], [], [885, 26, 183], [], [885, 26, 183], [], [], [], []]
