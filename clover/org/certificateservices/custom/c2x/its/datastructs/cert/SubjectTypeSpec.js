var clover = new Object();

// JSON: {classes : [{name, id, sl, el,  methods : [{sl, el}, ...]}, ...]}
clover.pageData = {"classes":[{"el":59,"id":10902,"methods":[{"el":42,"sc":2,"sl":29},{"el":57,"sc":2,"sl":44}],"name":"SubjectTypeSpec","sl":27}]}

// JSON: {test_ID : {"methods": [ID1, ID2, ID3...], "name" : "testXXX() void"}, ...};
clover.testTargets = {"test_321":{"methods":[{"sl":29}],"name":"Verify that enrollment_credential has bytevalue 0","pass":true,"statements":[{"sl":32},{"sl":33}]},"test_408":{"methods":[{"sl":29}],"name":"Verify that enrollment_authority has bytevalue 3","pass":true,"statements":[{"sl":32},{"sl":33}]},"test_462":{"methods":[{"sl":44}],"name":"Verify that SubjectType.getByValue returns enrollment_authority for 3","pass":true,"statements":[{"sl":47}]},"test_494":{"methods":[{"sl":29}],"name":"Verify that root_ca has bytevalue 4","pass":true,"statements":[{"sl":32},{"sl":33}]},"test_53":{"methods":[{"sl":29}],"name":"Verify that authorization_ticket has bytevalue 1","pass":true,"statements":[{"sl":32},{"sl":33}]},"test_536":{"methods":[{"sl":44}],"name":"Verify that SubjectType.getByValue returns enrollment_credential for 0","pass":true,"statements":[{"sl":47}]},"test_703":{"methods":[{"sl":44}],"name":"Verify that SubjectType.getByValue returns authorization_ticket for 1","pass":true,"statements":[{"sl":47}]},"test_843":{"methods":[{"sl":29}],"name":"Verify that authorization_authority has bytevalue 2","pass":true,"statements":[{"sl":32},{"sl":33}]},"test_877":{"methods":[{"sl":29}],"name":"Verify that crl_signer has bytevalue 5","pass":true,"statements":[{"sl":32},{"sl":33}]},"test_897":{"methods":[{"sl":44}],"name":"Verify that SubjectType.getByValue returns authorization_authority for 2","pass":true,"statements":[{"sl":47}]},"test_916":{"methods":[{"sl":44}],"name":"Verify that SubjectType.getByValue returns root_ca for 4","pass":true,"statements":[{"sl":47}]},"test_922":{"methods":[{"sl":44}],"name":"Verify that SubjectType.getByValue returns crl_signer for 5","pass":true,"statements":[{"sl":47}]}}

// JSON: { lines : [{tests : [testid1, testid2, testid3, ...]}, ...]};
clover.srcFileLines = [[], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [408, 494, 321, 53, 877, 843], [], [], [408, 494, 321, 53, 877, 843], [408, 494, 321, 53, 877, 843], [], [], [], [], [], [], [], [], [], [], [922, 703, 897, 536, 916, 462], [], [], [922, 703, 897, 536, 916, 462], [], [], [], [], [], [], [], [], [], [], [], []]
