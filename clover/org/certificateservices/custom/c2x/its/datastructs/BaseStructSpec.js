var clover = new Object();

// JSON: {classes : [{name, id, sl, el,  methods : [{sl, el}, ...]}, ...]}
clover.pageData = {"classes":[{"el":90,"id":5097,"methods":[{"el":53,"sc":2,"sl":44},{"el":63,"sc":2,"sl":55},{"el":88,"sc":2,"sl":66}],"name":"BaseStructSpec","sl":42}]}

// JSON: {test_ID : {"methods": [ID1, ID2, ID3...], "name" : "testXXX() void"}, ...};
clover.testTargets = {"test_1":{"methods":[{"sl":55}],"name":"Verify that deserialize decodes the value 0x01 properly into: 1","pass":true,"statements":[{"sl":56},{"sl":57},{"sl":59},{"sl":60},{"sl":62}]},"test_100":{"methods":[{"sl":44}],"name":"Verify that serialize ecodes the value 0x00 properly into: 0x00","pass":true,"statements":[{"sl":45},{"sl":46},{"sl":48},{"sl":49},{"sl":52}]},"test_109":{"methods":[{"sl":44}],"name":"Verify serialization","pass":true,"statements":[{"sl":45},{"sl":46},{"sl":48},{"sl":49},{"sl":52}]},"test_111":{"methods":[{"sl":44}],"name":"Verify serialization","pass":true,"statements":[{"sl":45},{"sl":46},{"sl":48},{"sl":49},{"sl":52}]},"test_115":{"methods":[{"sl":55}],"name":"Verify deserialization","pass":true,"statements":[{"sl":56},{"sl":57},{"sl":59},{"sl":60},{"sl":62}]},"test_12":{"methods":[{"sl":44}],"name":"Verify serialization","pass":true,"statements":[{"sl":45},{"sl":46},{"sl":48},{"sl":49},{"sl":52}]},"test_122":{"methods":[{"sl":44}],"name":"Verify that serialization produces correct output[2]","pass":true,"statements":[{"sl":45},{"sl":46},{"sl":48},{"sl":49},{"sl":52}]},"test_123":{"methods":[{"sl":55}],"name":"Verify getVerificationKey","pass":true,"statements":[{"sl":56},{"sl":57},{"sl":59},{"sl":60},{"sl":62}]},"test_130":{"methods":[{"sl":55}],"name":"Verify deserialization ofSignature","pass":true,"statements":[{"sl":56},{"sl":57},{"sl":59},{"sl":60},{"sl":62}]},"test_133":{"methods":[{"sl":55}],"name":"Verify deserialization","pass":true,"statements":[{"sl":56},{"sl":57},{"sl":59},{"sl":60},{"sl":62}]},"test_139":{"methods":[{"sl":55}],"name":"Verify deserialization of CrlSeries","pass":true,"statements":[{"sl":56},{"sl":57},{"sl":59},{"sl":60},{"sl":62}]},"test_14":{"methods":[{"sl":55}],"name":"Verify deserialization of EccPoint","pass":true,"statements":[{"sl":56},{"sl":57},{"sl":59},{"sl":60},{"sl":62}]},"test_149":{"methods":[{"sl":55}],"name":"Verify deserialization of a hash value","pass":true,"statements":[{"sl":56},{"sl":57},{"sl":59},{"sl":60},{"sl":62}]},"test_150":{"methods":[{"sl":55}],"name":"Verify deserialization ofSignature","pass":true,"statements":[{"sl":56},{"sl":57},{"sl":59},{"sl":60},{"sl":62}]},"test_153":{"methods":[{"sl":44}],"name":"Verify that serialize ecodes the value 0x0888 properly into: 0x8888","pass":true,"statements":[{"sl":45},{"sl":46},{"sl":48},{"sl":49},{"sl":52}]},"test_156":{"methods":[{"sl":44}],"name":"Verify serialization","pass":true,"statements":[{"sl":45},{"sl":46},{"sl":48},{"sl":49},{"sl":52}]},"test_158":{"methods":[{"sl":55}],"name":"Verify that findRecipientInfo find correct RecipientInfo","pass":true,"statements":[{"sl":56},{"sl":57},{"sl":59},{"sl":60},{"sl":62}]},"test_160":{"methods":[{"sl":44}],"name":"Verify serialization","pass":true,"statements":[{"sl":45},{"sl":46},{"sl":48},{"sl":49},{"sl":52}]},"test_161":{"methods":[{"sl":44}],"name":"Verify serialization of PublicKey","pass":true,"statements":[{"sl":45},{"sl":46},{"sl":48},{"sl":49},{"sl":52}]},"test_165":{"methods":[{"sl":55}],"name":"Verify deserialization","pass":true,"statements":[{"sl":56},{"sl":57},{"sl":59},{"sl":60},{"sl":62}]},"test_166":{"methods":[{"sl":55}],"name":"Verify that serializeCertWithoutSignature encodes the certificate without the signature correcly","pass":true,"statements":[{"sl":56},{"sl":57},{"sl":59},{"sl":60},{"sl":62}]},"test_169":{"methods":[{"sl":55}],"name":"Verify that deserialize decodes the value 0x8888 properly into: 2184","pass":true,"statements":[{"sl":56},{"sl":57},{"sl":59},{"sl":60},{"sl":62}]},"test_170":{"methods":[{"sl":44}],"name":"Verify serialization","pass":true,"statements":[{"sl":45},{"sl":46},{"sl":48},{"sl":49},{"sl":52}]},"test_173":{"methods":[{"sl":44}],"name":"Verify serialization","pass":true,"statements":[{"sl":45},{"sl":46},{"sl":48},{"sl":49},{"sl":52}]},"test_178":{"methods":[{"sl":44}],"name":"Verify serialization","pass":true,"statements":[{"sl":45},{"sl":46},{"sl":48},{"sl":49},{"sl":52}]},"test_183":{"methods":[{"sl":44}],"name":"Verify that serialization produces correct output[1]","pass":true,"statements":[{"sl":45},{"sl":46},{"sl":48},{"sl":49},{"sl":52}]},"test_184":{"methods":[{"sl":44}],"name":"Verify serialization","pass":true,"statements":[{"sl":45},{"sl":46},{"sl":48},{"sl":49},{"sl":52}]},"test_187":{"methods":[{"sl":55}],"name":"Verify deserialization","pass":true,"statements":[{"sl":56},{"sl":57},{"sl":59},{"sl":60},{"sl":62}]},"test_188":{"methods":[{"sl":55}],"name":"Verify deserialization","pass":true,"statements":[{"sl":56},{"sl":57},{"sl":59},{"sl":60},{"sl":62}]},"test_19":{"methods":[{"sl":44}],"name":"Verify serialization","pass":true,"statements":[{"sl":45},{"sl":46},{"sl":48},{"sl":49},{"sl":52}]},"test_194":{"methods":[{"sl":44}],"name":"Verify serialization of a hash value","pass":true,"statements":[{"sl":45},{"sl":46},{"sl":48},{"sl":49},{"sl":52}]},"test_196":{"methods":[{"sl":55}],"name":"Verify deserialization of PublicKey","pass":true,"statements":[{"sl":56},{"sl":57},{"sl":59},{"sl":60},{"sl":62}]},"test_198":{"methods":[{"sl":44}],"name":"Verify serialization of EciesNistP256EncryptedKey","pass":true,"statements":[{"sl":45},{"sl":46},{"sl":48},{"sl":49},{"sl":52}]},"test_199":{"methods":[{"sl":44}],"name":"Verify serialization of EccPoint","pass":true,"statements":[{"sl":45},{"sl":46},{"sl":48},{"sl":49},{"sl":52}]},"test_202":{"methods":[{"sl":55}],"name":"Verify deserialization","pass":true,"statements":[{"sl":56},{"sl":57},{"sl":59},{"sl":60},{"sl":62}]},"test_208":{"methods":[{"sl":55}],"name":"Verify deserialization","pass":true,"statements":[{"sl":56},{"sl":57},{"sl":59},{"sl":60},{"sl":62}]},"test_210":{"methods":[{"sl":55}],"name":"Verify deserialization of EciesNistP256EncryptedKey","pass":true,"statements":[{"sl":56},{"sl":57},{"sl":59},{"sl":60},{"sl":62}]},"test_221":{"methods":[{"sl":55}],"name":"Verify deserialization","pass":true,"statements":[{"sl":56},{"sl":57},{"sl":59},{"sl":60},{"sl":62}]},"test_226":{"methods":[{"sl":55}],"name":"Verify deserialization","pass":true,"statements":[{"sl":56},{"sl":57},{"sl":59},{"sl":60},{"sl":62}]},"test_229":{"methods":[{"sl":44}],"name":"Verify serialization of EncryptionParameters","pass":true,"statements":[{"sl":45},{"sl":46},{"sl":48},{"sl":49},{"sl":52}]},"test_230":{"methods":[{"sl":44}],"name":"Verify serialization","pass":true,"statements":[{"sl":45},{"sl":46},{"sl":48},{"sl":49},{"sl":52}]},"test_234":{"methods":[{"sl":55}],"name":"Verify deserialization","pass":true,"statements":[{"sl":56},{"sl":57},{"sl":59},{"sl":60},{"sl":62}]},"test_239":{"methods":[{"sl":55}],"name":"Verify deserialization","pass":true,"statements":[{"sl":56},{"sl":57},{"sl":59},{"sl":60},{"sl":62}]},"test_24":{"methods":[{"sl":44}],"name":"Verify serialization","pass":true,"statements":[{"sl":45},{"sl":46},{"sl":48},{"sl":49},{"sl":52}]},"test_271":{"methods":[{"sl":55}],"name":"Verify getEncryptionKey","pass":true,"statements":[{"sl":56},{"sl":57},{"sl":59},{"sl":60},{"sl":62}]},"test_280":{"methods":[{"sl":55}],"name":"Verify deserialization of EncryptionParameters","pass":true,"statements":[{"sl":56},{"sl":57},{"sl":59},{"sl":60},{"sl":62}]},"test_289":{"methods":[{"sl":44}],"name":"Verify serialization of RecipientInfo","pass":true,"statements":[{"sl":45},{"sl":46},{"sl":48},{"sl":49},{"sl":52}]},"test_294":{"methods":[{"sl":44}],"name":"Verify serialization","pass":true,"statements":[{"sl":45},{"sl":46},{"sl":48},{"sl":49},{"sl":52}]},"test_295":{"methods":[{"sl":44}],"name":"Verify serialization of Signature","pass":true,"statements":[{"sl":45},{"sl":46},{"sl":48},{"sl":49},{"sl":52}]},"test_297":{"methods":[{"sl":55}],"name":"Verify deserialization","pass":true,"statements":[{"sl":56},{"sl":57},{"sl":59},{"sl":60},{"sl":62}]},"test_3":{"methods":[{"sl":55}],"name":"Verify deserialization","pass":true,"statements":[{"sl":56},{"sl":57},{"sl":59},{"sl":60},{"sl":62}]},"test_304":{"methods":[{"sl":44}],"name":"Verify serialization","pass":true,"statements":[{"sl":45},{"sl":46},{"sl":48},{"sl":49},{"sl":52}]},"test_305":{"methods":[{"sl":44}],"name":"Verify that serialize ecodes the value 0x0a properly into: 0x0a","pass":true,"statements":[{"sl":45},{"sl":46},{"sl":48},{"sl":49},{"sl":52}]},"test_311":{"methods":[{"sl":44}],"name":"Verify serialization","pass":true,"statements":[{"sl":45},{"sl":46},{"sl":48},{"sl":49},{"sl":52}]},"test_322":{"methods":[{"sl":44},{"sl":55}],"name":"Verify deserialization and serialization of reference ETSI Certificates works","pass":true,"statements":[{"sl":45},{"sl":46},{"sl":48},{"sl":49},{"sl":52},{"sl":56},{"sl":57},{"sl":59},{"sl":60},{"sl":62}]},"test_336":{"methods":[{"sl":44}],"name":"Verify serialization of SubjectInfo","pass":true,"statements":[{"sl":45},{"sl":46},{"sl":48},{"sl":49},{"sl":52}]},"test_339":{"methods":[{"sl":44}],"name":"Verify serialization","pass":true,"statements":[{"sl":45},{"sl":46},{"sl":48},{"sl":49},{"sl":52}]},"test_34":{"methods":[{"sl":55}],"name":"Test to verifyCertificate","pass":true,"statements":[{"sl":56},{"sl":57},{"sl":59},{"sl":60},{"sl":62}]},"test_340":{"methods":[{"sl":44}],"name":"Verify serialization of RecipientInfo","pass":true,"statements":[{"sl":45},{"sl":46},{"sl":48},{"sl":49},{"sl":52}]},"test_346":{"methods":[{"sl":55}],"name":"Verify that deserialize decodes the value 0x0a properly into: 10","pass":true,"statements":[{"sl":56},{"sl":57},{"sl":59},{"sl":60},{"sl":62}]},"test_348":{"methods":[{"sl":55}],"name":"Verify deserialization","pass":true,"statements":[{"sl":56},{"sl":57},{"sl":59},{"sl":60},{"sl":62}]},"test_36":{"methods":[{"sl":44}],"name":"Verify that serialization produces correct output[0]","pass":true,"statements":[{"sl":45},{"sl":46},{"sl":48},{"sl":49},{"sl":52}]},"test_363":{"methods":[{"sl":55}],"name":"Verify deserialization","pass":true,"statements":[{"sl":56},{"sl":57},{"sl":59},{"sl":60},{"sl":62}]},"test_371":{"methods":[{"sl":55}],"name":"Verify that deserialize decodes the value 0x00 properly into: 0","pass":true,"statements":[{"sl":56},{"sl":57},{"sl":59},{"sl":60},{"sl":62}]},"test_374":{"methods":[{"sl":55}],"name":"Verify deserialization","pass":true,"statements":[{"sl":56},{"sl":57},{"sl":59},{"sl":60},{"sl":62}]},"test_389":{"methods":[{"sl":55}],"name":"Verify deserialization of EcdsaSignature","pass":true,"statements":[{"sl":56},{"sl":57},{"sl":59},{"sl":60},{"sl":62}]},"test_39":{"methods":[{"sl":44}],"name":"Verify serialization","pass":true,"statements":[{"sl":45},{"sl":46},{"sl":48},{"sl":49},{"sl":52}]},"test_40":{"methods":[{"sl":55}],"name":"Verify deserialization","pass":true,"statements":[{"sl":56},{"sl":57},{"sl":59},{"sl":60},{"sl":62}]},"test_46":{"methods":[{"sl":55}],"name":"Verify deserialization","pass":true,"statements":[{"sl":56},{"sl":57},{"sl":59},{"sl":60},{"sl":62}]},"test_49":{"methods":[{"sl":55}],"name":"Verify deserialization of EciesNistP256EncryptedKey","pass":true,"statements":[{"sl":56},{"sl":57},{"sl":59},{"sl":60},{"sl":62}]},"test_5":{"methods":[{"sl":44}],"name":"Verify serialization","pass":true,"statements":[{"sl":45},{"sl":46},{"sl":48},{"sl":49},{"sl":52}]},"test_54":{"methods":[{"sl":44}],"name":"Verify serialization of EcdsaSignature","pass":true,"statements":[{"sl":45},{"sl":46},{"sl":48},{"sl":49},{"sl":52}]},"test_60":{"methods":[{"sl":44}],"name":"Verify serialization","pass":true,"statements":[{"sl":45},{"sl":46},{"sl":48},{"sl":49},{"sl":52}]},"test_62":{"methods":[{"sl":55}],"name":"Verify deserialization","pass":true,"statements":[{"sl":56},{"sl":57},{"sl":59},{"sl":60},{"sl":62}]},"test_63":{"methods":[{"sl":55}],"name":"Verify deserialization","pass":true,"statements":[{"sl":56},{"sl":57},{"sl":59},{"sl":60},{"sl":62}]},"test_69":{"methods":[{"sl":44}],"name":"Verify serialization","pass":true,"statements":[{"sl":45},{"sl":46},{"sl":48},{"sl":49},{"sl":52}]},"test_75":{"methods":[{"sl":55}],"name":"Verify deserialization","pass":true,"statements":[{"sl":56},{"sl":57},{"sl":59},{"sl":60},{"sl":62}]},"test_8":{"methods":[{"sl":44}],"name":"Verify serialization of CrlSeries","pass":true,"statements":[{"sl":45},{"sl":46},{"sl":48},{"sl":49},{"sl":52}]},"test_81":{"methods":[{"sl":55}],"name":"Verify SignSecuredMessage using signer info type: certificate_digest_with_ecdsap256 generates a valid signature and that verifySecuredMessage can verify it.","pass":true,"statements":[{"sl":56},{"sl":57},{"sl":59},{"sl":60},{"sl":62}]},"test_84":{"methods":[{"sl":55}],"name":"Verify deserialization of EciesNistP256EncryptedKey","pass":true,"statements":[{"sl":56},{"sl":57},{"sl":59},{"sl":60},{"sl":62}]},"test_85":{"methods":[{"sl":55}],"name":"Verify SignSecuredMessage using signer info type: certificate generates a valid signature and that verifySecuredMessage can verify it.","pass":true,"statements":[{"sl":56},{"sl":57},{"sl":59},{"sl":60},{"sl":62}]},"test_88":{"methods":[{"sl":44}],"name":"Verify serialization","pass":true,"statements":[{"sl":45},{"sl":46},{"sl":48},{"sl":49},{"sl":52}]}}

// JSON: { lines : [{tests : [testid1, testid2, testid3, ...]}, ...]};
clover.srcFileLines = [[], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [311, 39, 36, 199, 5, 100, 12, 60, 198, 24, 173, 294, 88, 122, 289, 156, 322, 184, 161, 336, 111, 230, 54, 69, 304, 170, 153, 229, 160, 305, 295, 194, 8, 183, 109, 340, 339, 178, 19], [311, 39, 36, 199, 5, 100, 12, 60, 198, 24, 173, 294, 88, 122, 289, 156, 322, 184, 161, 336, 111, 230, 54, 69, 304, 170, 153, 229, 160, 305, 295, 194, 8, 183, 109, 340, 339, 178, 19], [311, 39, 36, 199, 5, 100, 12, 60, 198, 24, 173, 294, 88, 122, 289, 156, 322, 184, 161, 336, 111, 230, 54, 69, 304, 170, 153, 229, 160, 305, 295, 194, 8, 183, 109, 340, 339, 178, 19], [], [311, 39, 36, 199, 5, 100, 12, 60, 198, 24, 173, 294, 88, 122, 289, 156, 322, 184, 161, 336, 111, 230, 54, 69, 304, 170, 153, 229, 160, 305, 295, 194, 8, 183, 109, 340, 339, 178, 19], [311, 39, 36, 199, 5, 100, 12, 60, 198, 24, 173, 294, 88, 122, 289, 156, 322, 184, 161, 336, 111, 230, 54, 69, 304, 170, 153, 229, 160, 305, 295, 194, 8, 183, 109, 340, 339, 178, 19], [], [], [311, 39, 36, 199, 5, 100, 12, 60, 198, 24, 173, 294, 88, 122, 289, 156, 322, 184, 161, 336, 111, 230, 54, 69, 304, 170, 153, 229, 160, 305, 295, 194, 8, 183, 109, 340, 339, 178, 19], [], [], [133, 239, 210, 49, 297, 149, 158, 234, 346, 389, 196, 348, 169, 322, 208, 363, 202, 271, 34, 115, 374, 226, 85, 81, 188, 165, 139, 130, 123, 62, 166, 46, 75, 3, 14, 1, 371, 150, 187, 221, 40, 84, 63, 280], [133, 239, 210, 49, 297, 149, 158, 234, 346, 389, 196, 348, 169, 322, 208, 363, 202, 271, 34, 115, 374, 226, 85, 81, 188, 165, 139, 130, 123, 62, 166, 46, 75, 3, 14, 1, 371, 150, 187, 221, 40, 84, 63, 280], [133, 239, 210, 49, 297, 149, 158, 234, 346, 389, 196, 348, 169, 322, 208, 363, 202, 271, 34, 115, 374, 226, 85, 81, 188, 165, 139, 130, 123, 62, 166, 46, 75, 3, 14, 1, 371, 150, 187, 221, 40, 84, 63, 280], [], [133, 239, 210, 49, 297, 149, 158, 234, 346, 389, 196, 348, 169, 322, 208, 363, 202, 271, 34, 115, 374, 226, 85, 81, 188, 165, 139, 130, 123, 62, 166, 46, 75, 3, 14, 1, 371, 150, 187, 221, 40, 84, 63, 280], [133, 239, 210, 49, 297, 149, 158, 234, 346, 389, 196, 348, 169, 322, 208, 363, 202, 271, 34, 115, 374, 226, 85, 81, 188, 165, 139, 130, 123, 62, 166, 46, 75, 3, 14, 1, 371, 150, 187, 221, 40, 84, 63, 280], [], [133, 239, 210, 49, 297, 149, 158, 234, 346, 389, 196, 348, 169, 322, 208, 363, 202, 271, 34, 115, 374, 226, 85, 81, 188, 165, 139, 130, 123, 62, 166, 46, 75, 3, 14, 1, 371, 150, 187, 221, 40, 84, 63, 280], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], []]
