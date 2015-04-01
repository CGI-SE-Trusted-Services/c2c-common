var clover = new Object();

// JSON: {classes : [{name, id, sl, el,  methods : [{sl, el}, ...]}, ...]}
clover.pageData = {"classes":[{"el":59,"id":4286,"methods":[{"el":44,"sc":2,"sl":32},{"el":57,"sc":2,"sl":46}],"name":"EccPointTypeSpec","sl":30}]}

// JSON: {test_ID : {"methods": [ID1, ID2, ID3...], "name" : "testXXX() void"}, ...};
clover.testTargets = {"test_118":{"methods":[{"sl":46}],"name":"Verify that EccPointType.getByValue returns x_coordinate_only for 0","pass":true,"statements":[{"sl":49}]},"test_121":{"methods":[{"sl":46}],"name":"Verify that EccPointType.getByValue returns uncompressed for 4","pass":true,"statements":[{"sl":49}]},"test_167":{"methods":[{"sl":32}],"name":"Verify that uncompressed has bytevalue 4","pass":true,"statements":[{"sl":35},{"sl":36}]},"test_177":{"methods":[{"sl":32}],"name":"Verify that compressed_lsb_y_0 has bytevalue 2","pass":true,"statements":[{"sl":35},{"sl":36}]},"test_197":{"methods":[{"sl":32}],"name":"Verify that compressed_lsb_y_1 has bytevalue 3","pass":true,"statements":[{"sl":35},{"sl":36}]},"test_292":{"methods":[{"sl":32}],"name":"Verify that x_coordinate_only has bytevalue 0","pass":true,"statements":[{"sl":35},{"sl":36}]},"test_384":{"methods":[{"sl":46}],"name":"Verify that EccPointType.getByValue returns compressed_lsb_y_0 for 2","pass":true,"statements":[{"sl":49}]},"test_74":{"methods":[{"sl":46}],"name":"Verify that EccPointType.getByValue returns compressed_lsb_y_1 for 3","pass":true,"statements":[{"sl":49}]}}

// JSON: { lines : [{tests : [testid1, testid2, testid3, ...]}, ...]};
clover.srcFileLines = [[], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [292, 177, 167, 197], [], [], [292, 177, 167, 197], [292, 177, 167, 197], [], [], [], [], [], [], [], [], [], [384, 118, 74, 121], [], [], [384, 118, 74, 121], [], [], [], [], [], [], [], [], [], []]
