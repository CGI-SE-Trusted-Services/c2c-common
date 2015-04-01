var clover = new Object();

// JSON: {classes : [{name, id, sl, el,  methods : [{sl, el}, ...]}, ...]}
clover.pageData = {"classes":[{"el":59,"id":4286,"methods":[{"el":44,"sc":2,"sl":32},{"el":57,"sc":2,"sl":46}],"name":"EccPointTypeSpec","sl":30}]}

// JSON: {test_ID : {"methods": [ID1, ID2, ID3...], "name" : "testXXX() void"}, ...};
clover.testTargets = {"test_10":{"methods":[{"sl":46}],"name":"Verify that EccPointType.getByValue returns compressed_lsb_y_1 for 3","pass":true,"statements":[{"sl":49}]},"test_125":{"methods":[{"sl":46}],"name":"Verify that EccPointType.getByValue returns x_coordinate_only for 0","pass":true,"statements":[{"sl":49}]},"test_147":{"methods":[{"sl":46}],"name":"Verify that EccPointType.getByValue returns uncompressed for 4","pass":true,"statements":[{"sl":49}]},"test_188":{"methods":[{"sl":32}],"name":"Verify that compressed_lsb_y_1 has bytevalue 3","pass":true,"statements":[{"sl":35},{"sl":36}]},"test_249":{"methods":[{"sl":32}],"name":"Verify that uncompressed has bytevalue 4","pass":true,"statements":[{"sl":35},{"sl":36}]},"test_407":{"methods":[{"sl":32}],"name":"Verify that compressed_lsb_y_0 has bytevalue 2","pass":true,"statements":[{"sl":35},{"sl":36}]},"test_60":{"methods":[{"sl":46}],"name":"Verify that EccPointType.getByValue returns compressed_lsb_y_0 for 2","pass":true,"statements":[{"sl":49}]},"test_66":{"methods":[{"sl":32}],"name":"Verify that x_coordinate_only has bytevalue 0","pass":true,"statements":[{"sl":35},{"sl":36}]}}

// JSON: { lines : [{tests : [testid1, testid2, testid3, ...]}, ...]};
clover.srcFileLines = [[], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [66, 188, 407, 249], [], [], [66, 188, 407, 249], [66, 188, 407, 249], [], [], [], [], [], [], [], [], [], [125, 10, 60, 147], [], [], [125, 10, 60, 147], [], [], [], [], [], [], [], [], [], []]
