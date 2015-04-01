var clover = new Object();

// JSON: {classes : [{name, id, sl, el,  methods : [{sl, el}, ...]}, ...]}
clover.pageData = {"classes":[{"el":59,"id":4286,"methods":[{"el":44,"sc":2,"sl":32},{"el":57,"sc":2,"sl":46}],"name":"EccPointTypeSpec","sl":30}]}

// JSON: {test_ID : {"methods": [ID1, ID2, ID3...], "name" : "testXXX() void"}, ...};
clover.testTargets = {"test_105":{"methods":[{"sl":46}],"name":"Verify that EccPointType.getByValue returns uncompressed for 4","pass":true,"statements":[{"sl":49}]},"test_161":{"methods":[{"sl":46}],"name":"Verify that EccPointType.getByValue returns x_coordinate_only for 0","pass":true,"statements":[{"sl":49}]},"test_194":{"methods":[{"sl":32}],"name":"Verify that compressed_lsb_y_1 has bytevalue 3","pass":true,"statements":[{"sl":35},{"sl":36}]},"test_229":{"methods":[{"sl":32}],"name":"Verify that compressed_lsb_y_0 has bytevalue 2","pass":true,"statements":[{"sl":35},{"sl":36}]},"test_322":{"methods":[{"sl":46}],"name":"Verify that EccPointType.getByValue returns compressed_lsb_y_1 for 3","pass":true,"statements":[{"sl":49}]},"test_391":{"methods":[{"sl":32}],"name":"Verify that x_coordinate_only has bytevalue 0","pass":true,"statements":[{"sl":35},{"sl":36}]},"test_49":{"methods":[{"sl":46}],"name":"Verify that EccPointType.getByValue returns compressed_lsb_y_0 for 2","pass":true,"statements":[{"sl":49}]},"test_65":{"methods":[{"sl":32}],"name":"Verify that uncompressed has bytevalue 4","pass":true,"statements":[{"sl":35},{"sl":36}]}}

// JSON: { lines : [{tests : [testid1, testid2, testid3, ...]}, ...]};
clover.srcFileLines = [[], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [194, 391, 65, 229], [], [], [194, 391, 65, 229], [194, 391, 65, 229], [], [], [], [], [], [], [], [], [], [322, 49, 161, 105], [], [], [322, 49, 161, 105], [], [], [], [], [], [], [], [], [], []]
