var clover = new Object();

// JSON: {classes : [{name, id, sl, el,  methods : [{sl, el}, ...]}, ...]}
clover.pageData = {"classes":[{"el":169,"id":8130,"methods":[{"el":59,"sc":2,"sl":57},{"el":70,"sc":2,"sl":64},{"el":154,"sc":2,"sl":94},{"el":167,"sc":2,"sl":161}],"name":"BaseCertGenerator","sl":51}]}

// JSON: {test_ID : {"methods": [ID1, ID2, ID3...], "name" : "testXXX() void"}, ...};
clover.testTargets = {"test_253":{"methods":[{"sl":64},{"sl":94},{"sl":161}],"name":"Generate Authorization Credential with a certificate chain as signer info","pass":true,"statements":[{"sl":65},{"sl":66},{"sl":67},{"sl":68},{"sl":69},{"sl":112},{"sl":116},{"sl":117},{"sl":120},{"sl":122},{"sl":123},{"sl":124},{"sl":126},{"sl":127},{"sl":132},{"sl":134},{"sl":135},{"sl":143},{"sl":144},{"sl":145},{"sl":149},{"sl":151},{"sl":153},{"sl":162},{"sl":163},{"sl":164},{"sl":166}]},"test_315":{"methods":[{"sl":64},{"sl":94},{"sl":161}],"name":"Generate Authorization Ticket with a digest as signer info","pass":true,"statements":[{"sl":65},{"sl":66},{"sl":67},{"sl":68},{"sl":69},{"sl":112},{"sl":116},{"sl":117},{"sl":120},{"sl":122},{"sl":123},{"sl":124},{"sl":126},{"sl":127},{"sl":132},{"sl":134},{"sl":135},{"sl":143},{"sl":144},{"sl":145},{"sl":149},{"sl":151},{"sl":153},{"sl":162},{"sl":163},{"sl":164},{"sl":166}]},"test_379":{"methods":[{"sl":64},{"sl":94},{"sl":161}],"name":"Generate Enrollment Authority and verify that it is signed by the Root CA","pass":true,"statements":[{"sl":65},{"sl":66},{"sl":67},{"sl":68},{"sl":69},{"sl":112},{"sl":116},{"sl":117},{"sl":120},{"sl":122},{"sl":123},{"sl":124},{"sl":126},{"sl":127},{"sl":132},{"sl":134},{"sl":135},{"sl":143},{"sl":144},{"sl":145},{"sl":149},{"sl":151},{"sl":153},{"sl":162},{"sl":163},{"sl":164},{"sl":166}]},"test_450":{"methods":[{"sl":57},{"sl":64},{"sl":94},{"sl":161}],"name":"Generate Enrollment Credential v1 for interoperability testing","pass":true,"statements":[{"sl":58},{"sl":65},{"sl":66},{"sl":67},{"sl":68},{"sl":69},{"sl":112},{"sl":116},{"sl":117},{"sl":120},{"sl":122},{"sl":123},{"sl":124},{"sl":126},{"sl":127},{"sl":128},{"sl":130},{"sl":132},{"sl":134},{"sl":135},{"sl":143},{"sl":144},{"sl":145},{"sl":149},{"sl":151},{"sl":153},{"sl":162},{"sl":163},{"sl":164},{"sl":166}]},"test_501":{"methods":[{"sl":64},{"sl":94},{"sl":161}],"name":"Generate RootCA with Encryption Key and Geographic region and verify that all attributes are set.","pass":true,"statements":[{"sl":65},{"sl":66},{"sl":67},{"sl":68},{"sl":69},{"sl":112},{"sl":116},{"sl":117},{"sl":120},{"sl":122},{"sl":123},{"sl":124},{"sl":126},{"sl":127},{"sl":128},{"sl":130},{"sl":132},{"sl":134},{"sl":135},{"sl":143},{"sl":144},{"sl":145},{"sl":146},{"sl":149},{"sl":151},{"sl":153},{"sl":162},{"sl":163},{"sl":164},{"sl":166}]},"test_530":{"methods":[{"sl":64},{"sl":94},{"sl":161}],"name":"Generate Enrollment Credential with a certificate as signer info","pass":true,"statements":[{"sl":65},{"sl":66},{"sl":67},{"sl":68},{"sl":69},{"sl":112},{"sl":116},{"sl":117},{"sl":120},{"sl":122},{"sl":123},{"sl":124},{"sl":126},{"sl":127},{"sl":132},{"sl":134},{"sl":135},{"sl":143},{"sl":144},{"sl":145},{"sl":149},{"sl":151},{"sl":153},{"sl":162},{"sl":163},{"sl":164},{"sl":166}]},"test_66":{"methods":[{"sl":57},{"sl":64},{"sl":94},{"sl":161}],"name":"Generate Authorization CA v1 for interoperability testing","pass":true,"statements":[{"sl":58},{"sl":65},{"sl":66},{"sl":67},{"sl":68},{"sl":69},{"sl":112},{"sl":116},{"sl":117},{"sl":120},{"sl":122},{"sl":123},{"sl":124},{"sl":126},{"sl":127},{"sl":132},{"sl":134},{"sl":135},{"sl":143},{"sl":144},{"sl":145},{"sl":149},{"sl":151},{"sl":153},{"sl":162},{"sl":163},{"sl":164},{"sl":166}]},"test_669":{"methods":[{"sl":57},{"sl":64},{"sl":94},{"sl":161}],"name":"Generate Authorization Ticket and Signed Secured Message v1 for interoperability testing","pass":true,"statements":[{"sl":58},{"sl":65},{"sl":66},{"sl":67},{"sl":68},{"sl":69},{"sl":112},{"sl":116},{"sl":117},{"sl":120},{"sl":122},{"sl":123},{"sl":124},{"sl":126},{"sl":127},{"sl":132},{"sl":134},{"sl":135},{"sl":143},{"sl":144},{"sl":145},{"sl":149},{"sl":151},{"sl":153},{"sl":162},{"sl":163},{"sl":164},{"sl":166}]},"test_679":{"methods":[{"sl":64},{"sl":94},{"sl":161}],"name":"Generate RootCA without Encryption Key and Geographic region and verify that all other attributes are set.","pass":true,"statements":[{"sl":65},{"sl":66},{"sl":67},{"sl":68},{"sl":69},{"sl":112},{"sl":116},{"sl":117},{"sl":120},{"sl":122},{"sl":123},{"sl":124},{"sl":126},{"sl":127},{"sl":132},{"sl":134},{"sl":135},{"sl":143},{"sl":144},{"sl":145},{"sl":149},{"sl":151},{"sl":153},{"sl":162},{"sl":163},{"sl":164},{"sl":166}]},"test_682":{"methods":[{"sl":64},{"sl":94},{"sl":161}],"name":"Generate Enrollment Credential with a digest as signer info","pass":true,"statements":[{"sl":65},{"sl":66},{"sl":67},{"sl":68},{"sl":69},{"sl":112},{"sl":116},{"sl":117},{"sl":120},{"sl":122},{"sl":123},{"sl":124},{"sl":126},{"sl":127},{"sl":132},{"sl":134},{"sl":135},{"sl":143},{"sl":144},{"sl":145},{"sl":149},{"sl":151},{"sl":153},{"sl":162},{"sl":163},{"sl":164},{"sl":166}]},"test_728":{"methods":[{"sl":94}],"name":"Verify illegal subjec type no root ca and CA certificate null throws illegal argument exception","pass":true,"statements":[{"sl":112},{"sl":113}]},"test_808":{"methods":[{"sl":64},{"sl":94},{"sl":161}],"name":"Generate Authorization Ticket with a certificate as signer info","pass":true,"statements":[{"sl":65},{"sl":66},{"sl":67},{"sl":68},{"sl":69},{"sl":112},{"sl":116},{"sl":117},{"sl":120},{"sl":122},{"sl":123},{"sl":124},{"sl":126},{"sl":127},{"sl":132},{"sl":134},{"sl":135},{"sl":143},{"sl":144},{"sl":145},{"sl":149},{"sl":151},{"sl":153},{"sl":162},{"sl":163},{"sl":164},{"sl":166}]},"test_868":{"methods":[{"sl":64},{"sl":94},{"sl":161}],"name":"Generate Enrollment Credential with a certificate chain as signer info","pass":true,"statements":[{"sl":65},{"sl":66},{"sl":67},{"sl":68},{"sl":69},{"sl":112},{"sl":116},{"sl":117},{"sl":120},{"sl":122},{"sl":123},{"sl":124},{"sl":126},{"sl":127},{"sl":132},{"sl":134},{"sl":135},{"sl":143},{"sl":144},{"sl":145},{"sl":149},{"sl":151},{"sl":153},{"sl":162},{"sl":163},{"sl":164},{"sl":166}]},"test_959":{"methods":[{"sl":64},{"sl":94},{"sl":161}],"name":"Generate Authorization Authority and verify that it is signed by the Root CA","pass":true,"statements":[{"sl":65},{"sl":66},{"sl":67},{"sl":68},{"sl":69},{"sl":112},{"sl":116},{"sl":117},{"sl":120},{"sl":122},{"sl":123},{"sl":124},{"sl":126},{"sl":127},{"sl":132},{"sl":134},{"sl":135},{"sl":143},{"sl":144},{"sl":145},{"sl":149},{"sl":151},{"sl":153},{"sl":162},{"sl":163},{"sl":164},{"sl":166}]}}

// JSON: { lines : [{tests : [testid1, testid2, testid3, ...]}, ...]};
clover.srcFileLines = [[], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [669, 66, 450], [669, 66, 450], [], [], [], [], [], [868, 669, 682, 66, 530, 253, 379, 450, 315, 679, 959, 808, 501], [868, 669, 682, 66, 530, 253, 379, 450, 315, 679, 959, 808, 501], [868, 669, 682, 66, 530, 253, 379, 450, 315, 679, 959, 808, 501], [868, 669, 682, 66, 530, 253, 379, 450, 315, 679, 959, 808, 501], [868, 669, 682, 66, 530, 253, 379, 450, 315, 679, 959, 808, 501], [868, 669, 682, 66, 530, 253, 379, 450, 315, 679, 959, 808, 501], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [868, 669, 682, 66, 728, 530, 253, 379, 450, 315, 679, 959, 808, 501], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [868, 669, 682, 66, 728, 530, 253, 379, 450, 315, 679, 959, 808, 501], [728], [], [], [868, 669, 682, 66, 530, 253, 379, 450, 315, 679, 959, 808, 501], [868, 669, 682, 66, 530, 253, 379, 450, 315, 679, 959, 808, 501], [], [], [868, 669, 682, 66, 530, 253, 379, 450, 315, 679, 959, 808, 501], [], [868, 669, 682, 66, 530, 253, 379, 450, 315, 679, 959, 808, 501], [868, 669, 682, 66, 530, 253, 379, 450, 315, 679, 959, 808, 501], [868, 669, 682, 66, 530, 253, 379, 450, 315, 679, 959, 808, 501], [], [868, 669, 682, 66, 530, 253, 379, 450, 315, 679, 959, 808, 501], [868, 669, 682, 66, 530, 253, 379, 450, 315, 679, 959, 808, 501], [450, 501], [], [450, 501], [], [868, 669, 682, 66, 530, 253, 379, 450, 315, 679, 959, 808, 501], [], [868, 669, 682, 66, 530, 253, 379, 450, 315, 679, 959, 808, 501], [868, 669, 682, 66, 530, 253, 379, 450, 315, 679, 959, 808, 501], [], [], [], [], [], [], [], [868, 669, 682, 66, 530, 253, 379, 450, 315, 679, 959, 808, 501], [868, 669, 682, 66, 530, 253, 379, 450, 315, 679, 959, 808, 501], [868, 669, 682, 66, 530, 253, 379, 450, 315, 679, 959, 808, 501], [501], [], [], [868, 669, 682, 66, 530, 253, 379, 450, 315, 679, 959, 808, 501], [], [868, 669, 682, 66, 530, 253, 379, 450, 315, 679, 959, 808, 501], [], [868, 669, 682, 66, 530, 253, 379, 450, 315, 679, 959, 808, 501], [], [], [], [], [], [], [], [868, 669, 682, 66, 530, 253, 379, 450, 315, 679, 959, 808, 501], [868, 669, 682, 66, 530, 253, 379, 450, 315, 679, 959, 808, 501], [868, 669, 682, 66, 530, 253, 379, 450, 315, 679, 959, 808, 501], [868, 669, 682, 66, 530, 253, 379, 450, 315, 679, 959, 808, 501], [], [868, 669, 682, 66, 530, 253, 379, 450, 315, 679, 959, 808, 501], [], [], []]
