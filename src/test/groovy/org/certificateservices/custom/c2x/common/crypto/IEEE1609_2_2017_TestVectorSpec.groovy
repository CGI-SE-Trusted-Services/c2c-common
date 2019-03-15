/************************************************************************
 *                                                                       *
 *  Certificate Service -  Car2Car Core                                  *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Affero General Public License   *
 *  License as published by the Free Software Foundation; either         *
 *  version 3   of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.certificateservices.custom.c2x.common.crypto


import org.bouncycastle.crypto.agreement.ECDHCBasicAgreement
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.KDF2BytesGenerator
import org.bouncycastle.crypto.params.*
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.spec.ECParameterSpec
import org.bouncycastle.jce.spec.ECPrivateKeySpec
import org.bouncycastle.math.ec.ECPoint
import org.bouncycastle.util.BigIntegers
import org.bouncycastle.util.encoders.Hex
import org.certificateservices.custom.c2x.common.BaseStructSpec
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EccP256CurvePoint
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EciesP256EncryptedKey
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PublicVerificationKey
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SymmAlgorithm
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.EncryptedDataEncryptionKey
import spock.lang.Shared
import spock.lang.Unroll

import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec
import java.security.Key
import java.security.KeyFactory
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey

/**
 * Cryptographic Test Vector verifications specified in Appendix D of 2017 amendment of IEEE 1609.2.
 *
 */
class IEEE1609_2_2017_TestVectorSpec extends BaseStructSpec{

    @Shared DefaultCryptoManager cryptoManager

    def setupSpec(){
        cryptoManager = new DefaultCryptoManager()
        cryptoManager.setupAndConnect(new DefaultCryptoManagerParams("BC"))
    }

    /**
     * D 6.1 AES-CCM-128
     */
    static final byte[] testvector_AES_D_6_1_1_K = Hex.decode("E58D5C8F8C9ED9785679E08ABC7C8116")
    static final byte[] testvector_AES_D_6_1_1_N = Hex.decode("A9F593C09EAEEA8BF0C1CF6A")
    static final byte[] testvector_AES_D_6_1_1_P = Hex.decode("0653B5714D1357F4995BDDACBE10873951A1EBA663718D1AF35D2F0D52C79DE49BE622C4A6" +
            "D90647BA2B004C3E8AE422FD27063AFA19AD883DCCBD97D98B8B0461B5671E75F19701C24042" +
            "B8D3AF79B9FF62BC448EF9440B1EA3F7E5C0F4BFEFE3E326E62D5EE4CB4B4CFFF30AD5F49A79" +
            "81ABF71617245B96E522E1ADD78A")
    static final byte[] testvector_AES_D_6_1_1_C_T = Hex.decode("5F82B9FCE34B94835395DD89D71FB758D2A3907FBF2FD58994A2B9CF8725AF26F0B23853C27A" +
            "06E35EE72CAD827713C18FA5DDA971D9BAA7B42A301FF60C6E4AD651C1BB6ED4F25F7D0FF38" +
            "7A11627934CD11F86984EA3AC969DDA9A020AD6424B0D393E3FB4B1119ADF5CDB012A59753E4" +
            "1D47E5E5A8C3A118ED407049B56D53BF56CB38C0B20A2502D1DA70B9761")

    static final byte[] testvector_AES_D_6_1_2_K = Hex.decode("E58D5C8F8C9ED9785679E08ABC7C8116")
    static final byte[] testvector_AES_D_6_1_2_N = Hex.decode("A9F593C09EAEEA8BF0C1CF6A")
    static final byte[] testvector_AES_D_6_1_2_P = Hex.decode("ACA650CCCCDA604E16A8B54A3335E0BC2FD9444F33E3D9B82AFE6F445357634974F0F1728CF" +
            "113452321CBE5858304B01D4A14AE7F3B45980EE8033AD2A8599B78C29494C9E5F8945A8CADE3" +
            "EB5A30D156C0D83271626DADDB650954093443FBAC9701C02E5A973F39C2E1761A4B48C764BF6" +
            "DB215A54B285A06ECA3AF0A83F7")
    static final byte[] testvector_AES_D_6_1_2_C_T = Hex.decode("F5775C416282A339DC66B56F5A3AD0DDACDB3F96EFBD812B4D01F98686B5518B1FA4EBE5E8" +
            "5213E1C7EDE704397EF3536FC8CF3DF4FB52B7870E8EB2FD2FBCD5CF263231D2C09DCAE5C31C" +
            "DC99E36EFBE5737BF067D58A0A535B242BCBCA2A5604791E183CB0C2E5E851425E11B4E528237" +
            "F123B5DE8E349DD6D1A4506465F7257001080003872271900D3F39C9661FD")

    static final byte[] testvector_AES_D_6_1_3_K = Hex.decode("E58D5C8F8C9ED9785679E08ABC7C8116")
    static final byte[] testvector_AES_D_6_1_3_N = Hex.decode("A9F593C09EAEEA8BF0C1CF6A")
    static final byte[] testvector_AES_D_6_1_3_P = Hex.decode("D1AA8BBC04DFC92FFE2CB7748E70B02F5A91DA14781223A712D44C4BA14A1C78EB02387FE7" +
            "3FDCBCA8447056ACAA9B5F94D5208972B706DF9FC4C803EABB2BC58C3D8DF4AC496C34CB6B" +
            "AB939478CB417995B2314DAF7AF3F4C8A8D5D57A03F0EB2B7BBD2D16BABBF22C5B1EEBFF72" +
            "C7DD4F912D5821F9A6BFA2D063CE6F6648DF")
    static final byte[] testvector_AES_D_6_1_3_C_T = Hex.decode("887B8731AA870A5834E2B751E77F804ED993A1CDA44C7B34752BDA8974A82EBA805622E8839" +
            "CDC184C885CB710576CBCE657FB1AF97711F01622458BC53CCE8B3BD92B51B76C096A74241AA" +
            "CE6C1956BCA2611F35B189D547CF685AA17846A5D43C564653FFCEF6123BFF836E000DF289A8F" +
            "EEA4106C51C738C926856723BACDB3F5D0F87F7E29D94BF1B41DE8063E1071")

    static final byte[] testvector_AES_D_6_1_4_K = Hex.decode("B8453A728060F8D517BACEED3829F4D9")
    static final byte[] testvector_AES_D_6_1_4_N = Hex.decode("CFBCE69C884D5BABBBAAF9A3")
    static final byte[] testvector_AES_D_6_1_4_P = Hex.decode("F7629B73DAE85A9BCA45C42EB7FC1818DC74A60E13AE65A043E24B5A4D3AE04C273E7D6F42" +
            "710F2D223D09EB7C1315718A5A1293D482E4C45C3E852E5106AAD7B695A02C4854801A5EFE937" +
            "A6540BCE8734E8141558C3433B1D4C733DC5EF9C47B5279AA46EE3D8BD33B0950BE5C9EBDF18" +
            "BCF069B6DAF82FF1186912F0ABA")
    static final byte[] testvector_AES_D_6_1_4_C_T = Hex.decode("DEDE575B6EFE390F2CBB4F368A711F6CDF69ABD11AF580B2BF4029F85EB835D1ABDDB30E9" +
            "E9CF3F13CBA3BCC2E918713D218AF0D07CC614AF69892AFA986AF2D5E60EDB05D09D3B29E2A" +
            "65B543AD6F26E5D76B660FE9184906A6315CD6B5355FA291A1E90C510DF20E46C116E2180009C2" +
            "87659DB8D45CC3968049FA29F08DE5D156EDF7B0DBC84E410F292868C4BE")

    static final byte[] testvector_AES_D_6_1_5_K = Hex.decode("B8453A728060F8D517BACEED3829F4D9")
    static final byte[] testvector_AES_D_6_1_5_N = Hex.decode("CFBCE69C884D5BABBBAAF9A3")
    static final byte[] testvector_AES_D_6_1_5_P = Hex.decode("29B4013F552FBCE993544CC6605CB05C62A7894C4C99E6A12C5F9F2EE4DFBEBAD70CDD0893" +
            "542240F28BB5FBB9090332ED110ABFAE6C4C6460D916F8994136575B5A6FD8DB605FDF14CB819" +
            "77AFF7F99B5272580BF220133C691B09BADC4D1FE7125FD17FDBFC103E3F00A4D8E5A6F1E3D3" +
            "AF2A908535DE858E1CCD3DB4D1835")
    static final byte[] testvector_AES_D_6_1_5_C_T = Hex.decode("0008CD17E139DF7D75AAC7DE5DD1B72861BA849345C203B3D0FDFD8CF75D6B275BEF13694F" +
            "B9DE9CEC0C87DCEB8B9150B553B7217D22C9EACA7F017961C133ADB3AF2244CE3D0C77D41F7" +
            "7585C12AC5723BECFA7E5472D4971E346F4A72F1D65A8E62554B700F17A3E8DC20BD21EF1AA0E" +
            "3658322BEAAEA9317003B8DDB72FFDFA0834974152B95BADE2DF83D7EEC455")

    static final byte[] testvector_AES_D_6_1_6_K = Hex.decode("B8453A728060F8D517BACEED3829F4D9")
    static final byte[] testvector_AES_D_6_1_6_N = Hex.decode("CFBCE69C884D5BABBBAAF9A3")
    static final byte[] testvector_AES_D_6_1_6_P = Hex.decode("1D76BDF0626A7134BEB28A90D54ED7796C4C9535465C090C4B583A8CD40EF0A3864E7C07CC" +
            "AED140DF6B9D73234E652F8FF425FC206F63DFAB7DCDBBBE30411A14695E72A2BD8C4BFB1D6" +
            "991DB4F99EEA7435E55261E37FDF57CE79DF725C810192F5E6E0331ED62EB8A72C5B9DA6DFD97" +
            "48B3D168A69BAB33319EFD1E84EF2570")
    static final byte[] testvector_AES_D_6_1_6_C_T = Hex.decode("34CA71D8D67C12A0584C0188E8C3D00D6F5198EA4F07EC1EB7FA582EC78C253E0AADB26610" +
            "432D9CC1ECAF5471CCF74DD7B69862F321E65101DBDA3A46B044E0FC9C13EEB7E0DFE33BC99" +
            "F5EFDA24A2031DAB4727C7B1B87420E11F2FDCE048BC0EC862D498EDD1B36F7BA83E59EF349" +
            "A444194A4B1F68EA5AA05196187ED8ED684826C0C356A9B8EDA55BD91C2BA1022B")

    @Unroll
    def "Verify that IEEE 1609.2 2017 test vectors for section #section AES-CCM-128 is correct"(){
        when:
        byte[] c_t = cryptoManager.symmetricEncryptIEEE1609_2_2017(SymmAlgorithm.aes128Ccm,P,K,N)
        byte[] r_p = cryptoManager.symmetricDecryptIEEE1609_2_2017(SymmAlgorithm.aes128Ccm,c_t,K,N)
        then:
        Hex.toHexString(c_t) == Hex.toHexString(expectedCT)
        Hex.toHexString(r_p) == Hex.toHexString(P)
        where:
        section   | K                        | N                        | P                        | expectedCT
        "D 6.1.1" | testvector_AES_D_6_1_1_K | testvector_AES_D_6_1_1_N | testvector_AES_D_6_1_1_P | testvector_AES_D_6_1_1_C_T
        "D 6.1.2" | testvector_AES_D_6_1_2_K | testvector_AES_D_6_1_2_N | testvector_AES_D_6_1_2_P | testvector_AES_D_6_1_2_C_T
        "D 6.1.3" | testvector_AES_D_6_1_3_K | testvector_AES_D_6_1_3_N | testvector_AES_D_6_1_3_P | testvector_AES_D_6_1_3_C_T
        "D 6.1.4" | testvector_AES_D_6_1_4_K | testvector_AES_D_6_1_4_N | testvector_AES_D_6_1_4_P | testvector_AES_D_6_1_4_C_T
        "D 6.1.5" | testvector_AES_D_6_1_5_K | testvector_AES_D_6_1_5_N | testvector_AES_D_6_1_5_P | testvector_AES_D_6_1_5_C_T
        "D 6.1.6" | testvector_AES_D_6_1_6_K | testvector_AES_D_6_1_6_N | testvector_AES_D_6_1_6_P | testvector_AES_D_6_1_6_C_T
    }


    /**
     * D 6.2 ECIES Test vector, with correction of faulty P1 value after looking at the test vector generation source.
     * In the IEEE standard has the K and P1 the same value, but in the actual test they are different.
     */
    static byte[] testVector_ECIES_D6_2_1_empherical_privateKey = Hex.decode("1384C31D6982D52BCA3BED8A7E60F52FECDAB44E5C0EA166815A8159E09FFB42")
    static String testVector_ECIES_D6_2_1_recipient_privateKey = "060E41440A4E35154CA0EFCB52412145836AD032833E6BC781E533BF14851085"
    static byte[] testVector_ECIES_D6_2_1_recipient_publicKey_x = Hex.decode("8C5E20FE31935F6FA682A1F6D46E4468534FFEA1A698B14B0B12513EED8DEB11")
    static byte[] testVector_ECIES_D6_2_1_recipient_publicKey_y = Hex.decode("1270FEC2427E6A154DFCAE3368584396C8251A04E2AE7D87B016FF65D22D6F9E")
    static byte[] testVector_ECIES_D6_2_1_symKey = Hex.decode("9169155B08B07674CBADF75FB46A7B0D")
    static byte[] testVector_ECIES_D6_2_1_recipientHash = Hex.decode("A6B7B52554B4203F7E3ACFDB3A3ED8674EE086CE5906A7CAC2F8A398306D3BE9")
    static byte[] testVector_ECIES_D6_2_1_empherical_publicKey_x = Hex.decode("F45A99137B1BB2C150D6D8CF7292CA07DA68C003DAA766A9AF7F67F5EE916828")
    static byte[] testVector_ECIES_D6_2_1_empherical_publicKey_y = Hex.decode("F6A25216F44CB64A96C229AE00B479857B3B81C1319FB2ADF0E8DB2681769729")
    static byte[] testVector_ECIES_D6_2_1_C= Hex.decode("A6342013D623AD6C5F6882469673AE33")
    static byte[] testVector_ECIES_D6_2_1_T= Hex.decode("80e1d85d30f1bae4ecf1a534a89a0786")

    static byte[] testVector_ECIES_D6_2_3_empherical_privateKey = Hex.decode("1384C31D6982D52BCA3BED8A7E60F52FECDAB44E5C0EA166815A8159E09FFB42")
    static String testVector_ECIES_D6_2_3_recipient_privateKey = "DA5E1D853FCC5D0C162A245B9F29D38EB6059F0DB172FB7FDA6663B925E8C744"
    static byte[] testVector_ECIES_D6_2_3_recipient_publicKey_x = Hex.decode("8008B06FC4C9F9856048DA186E7DC390963D6A424E80B274FB75D12188D7D73F")
    static byte[] testVector_ECIES_D6_2_3_recipient_publicKey_y = Hex.decode("2774FB9600F27D7B3BBB2F7FCD8D2C96D4619EF9B4692C6A7C5733B5BAC8B27D")
    static byte[] testVector_ECIES_D6_2_3_symKey = Hex.decode("687E9757DEBFD87B0C267330C183C7B6")
    static byte[] testVector_ECIES_D6_2_3_recipientHash = Hex.decode("05BED5F867B89F30FE5552DF414B65B9DD4073FC385D14921C641A145AA12051")
    static byte[] testVector_ECIES_D6_2_3_empherical_publicKey_x = Hex.decode("F45A99137B1BB2C150D6D8CF7292CA07DA68C003DAA766A9AF7F67F5EE916828")
    static byte[] testVector_ECIES_D6_2_3_empherical_publicKey_y = Hex.decode("F6A25216F44CB64A96C229AE00B479857B3B81C1319FB2ADF0E8DB2681769729")
    static byte[] testVector_ECIES_D6_2_3_C= Hex.decode("1F6346EDAEAF57561FC9604FEBEFF44E")
    static byte[] testVector_ECIES_D6_2_3_T= Hex.decode("373c0fa7c52a0798ec36eadfe387c3ef")

    @Unroll
    def "Verify that IEEE 1609.2 2017 test vectors for section #section ECIES is correct (with corrected P1)"(){
        setup:
        SecretKey secretKey = new SecretKeySpec(key, "AES")
        EccP256CurvePoint uncompressed_point = new EccP256CurvePoint(rPubX,rPubY)
        ECPublicKey recipientPublicKey = cryptoManager.decodeEccPoint(PublicVerificationKey.PublicVerificationKeyChoices.ecdsaNistP256, uncompressed_point)
        when:

        EncryptedDataEncryptionKey res = cryptoManager.ieeeEceisEncryptSymmetricKey2017(EncryptedDataEncryptionKey.EncryptedDataEncryptionKeyChoices.eciesNistP256,recipientPublicKey, secretKey, p1,vPriv)
        EciesP256EncryptedKey  encryptedKey = res.value
        ECPublicKey ecPublicKey = cryptoManager.decodeEccPoint(EncryptedDataEncryptionKey.EncryptedDataEncryptionKeyChoices.eciesNistP256,encryptedKey.v)
        then:
        ecPublicKey.w.affineX.toString(16) == Hex.toHexString(vPubX)
        ecPublicKey.w.affineY.toString(16) == Hex.toHexString(vPubY)

        Hex.toHexString(encryptedKey.c) == Hex.toHexString(expectedC)
        Hex.toHexString(encryptedKey.t) == Hex.toHexString(expectedT)

        when:
        ECParameterSpec ecNistP256Spec = ECNamedCurveTable.getParameterSpec("P-256")
        ECPrivateKeySpec recipientPrivateKeySpec = new ECPrivateKeySpec(new BigInteger(rPriv,16), ecNistP256Spec)
        KeyFactory kf = KeyFactory.getInstance("EC", "BC")
        ECPrivateKey recipientPrivateKey = kf.generatePrivate(recipientPrivateKeySpec)

        Key decryptedKey = cryptoManager.ieeeEceisDecryptSymmetricKey2017(res, recipientPrivateKey, p1)

        then:
        Hex.toHexString(decryptedKey.encoded) == Hex.toHexString(key)

        when: // Test without pregenerated empherical key according to section 6.3.2 and 6.3.4
        res = cryptoManager.ieeeEceisEncryptSymmetricKey2017(EncryptedDataEncryptionKey.EncryptedDataEncryptionKeyChoices.eciesNistP256,recipientPublicKey, secretKey,p1)
        encryptedKey = res.value
        ecPublicKey = cryptoManager.decodeEccPoint(EncryptedDataEncryptionKey.EncryptedDataEncryptionKeyChoices.eciesNistP256,encryptedKey.v)

        then:
        ecPublicKey.w.affineX.toString(16) != Hex.toHexString(vPubX)
        ecPublicKey.w.affineY.toString(16) != Hex.toHexString(vPubY)

        when:
        decryptedKey = cryptoManager.ieeeEceisDecryptSymmetricKey2017(res, recipientPrivateKey, p1)

        then:
        Hex.toHexString(decryptedKey.encoded) == Hex.toHexString(key)

        where:
        section << ["D 6.3.1 and D 6.3.2","D 6.3.3 and D 6.3.4"]
        key << [testVector_ECIES_D6_2_1_symKey, testVector_ECIES_D6_2_3_symKey]
        rPriv << [testVector_ECIES_D6_2_1_recipient_privateKey,testVector_ECIES_D6_2_3_recipient_privateKey]
        rPubX << [testVector_ECIES_D6_2_1_recipient_publicKey_x,testVector_ECIES_D6_2_3_recipient_publicKey_x]
        rPubY << [testVector_ECIES_D6_2_1_recipient_publicKey_y,testVector_ECIES_D6_2_3_recipient_publicKey_y]
        vPriv << [testVector_ECIES_D6_2_1_empherical_privateKey,testVector_ECIES_D6_2_3_empherical_privateKey]
        vPubX << [testVector_ECIES_D6_2_1_empherical_publicKey_x,testVector_ECIES_D6_2_3_empherical_publicKey_x]
        vPubY << [testVector_ECIES_D6_2_1_empherical_publicKey_y,testVector_ECIES_D6_2_3_empherical_publicKey_y]
        p1 << [testVector_ECIES_D6_2_1_recipientHash,testVector_ECIES_D6_2_3_recipientHash]
        expectedC << [testVector_ECIES_D6_2_1_C,testVector_ECIES_D6_2_3_C]
        expectedT << [testVector_ECIES_D6_2_1_T,testVector_ECIES_D6_2_3_T]
    }


    /**
     * D 6.3 MAC1
     */
    static final byte[] testvector_MAC1_D_6_3_1_K = Hex.decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
    static final byte[] testvector_MAC1_D_6_3_1_M= Hex.decode("4869205468657265")
    static final byte[] testvector_MAC1_D_6_3_1_T= Hex.decode("b0344c61d8db38535ca8afceaf0bf12b")

    static final byte[] testvector_MAC1_D_6_3_2_K = Hex.decode("4a656665")
    static final byte[] testvector_MAC1_D_6_3_2_M= Hex.decode("7768617420646f2079612077616e7420666f72206e6f7468696e673f")
    static final byte[] testvector_MAC1_D_6_3_2_T= Hex.decode("5bdcc146bf60754e6a042426089575c7")

    static final byte[] testvector_MAC1_D_6_3_3_K = Hex.decode("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    static final byte[] testvector_MAC1_D_6_3_3_M= Hex.decode("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd")
    static final byte[] testvector_MAC1_D_6_3_3_T= Hex.decode("773ea91e36800e46854db8ebd09181a7")

    static final byte[] testvector_MAC1_D_6_3_4_K = Hex.decode("0102030405060708090a0b0c0d0e0f10111213141516171819")
    static final byte[] testvector_MAC1_D_6_3_4_M= Hex.decode("cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd")
    static final byte[] testvector_MAC1_D_6_3_4_T= Hex.decode("82558a389a443c0ea4cc819899f2083a")

    static final byte[] testvector_MAC1_D_6_3_5_K = Hex.decode("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c")
    static final byte[] testvector_MAC1_D_6_3_5_M= Hex.decode("546573742057697468205472756e636174696f6e")
    static final byte[] testvector_MAC1_D_6_3_5_T= Hex.decode("a3b6167473100ee06e0c796c2955552b")

    static final byte[] testvector_MAC1_D_6_3_6_K = Hex.decode("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    static final byte[] testvector_MAC1_D_6_3_6_M= Hex.decode("54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374")
    static final byte[] testvector_MAC1_D_6_3_6_T= Hex.decode("60e431591ee0b67f0d8a26aacbf5b77f")

    static final byte[] testvector_MAC1_D_6_3_7_K = Hex.decode("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n" +
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n" +
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    static final byte[] testvector_MAC1_D_6_3_7_M= Hex.decode("5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d736" +
            "97a65206b657920616e642061206c6172676572207468616e20626c6f636b2d73697a6520646174612e2054" +
            "6865206b6579206e6565647320746f20626520686173686564206265666f7265206265696e6720757365642" +
            "062792074686520484d414320616c676f726974686d2e")
    static final byte[] testvector_MAC1_D_6_3_7_T= Hex.decode("9b09ffa71b942fcb27635fbcd5b0e944")

    @Unroll
    def "Verify that IEEE 1609.2 2017 test vectors for section #section MAC1 is correct"(){
        setup:
        Mac1 mac1 = new Mac1(new SHA256Digest(),128)

        when:
        KeyParameter key = new KeyParameter(K)
        mac1.init(key)
        mac1.update(M,0,M.length)
        byte[] rest_T = new byte[16]
        mac1.doFinal(rest_T,0)
        then:
        Hex.encode(rest_T) == Hex.encode(expectedT)

        where:
        section   | K                                     | M                                               | expectedT
        "D 6.3.1" | testvector_MAC1_D_6_3_1_K             | testvector_MAC1_D_6_3_1_M                       | testvector_MAC1_D_6_3_1_T
        "D 6.3.2" | testvector_MAC1_D_6_3_2_K             | testvector_MAC1_D_6_3_2_M                       | testvector_MAC1_D_6_3_2_T
        "D 6.3.3" | testvector_MAC1_D_6_3_3_K             | testvector_MAC1_D_6_3_3_M                       | testvector_MAC1_D_6_3_3_T
        "D 6.3.4" | testvector_MAC1_D_6_3_4_K             | testvector_MAC1_D_6_3_4_M                       | testvector_MAC1_D_6_3_4_T
        "D 6.3.5" | testvector_MAC1_D_6_3_5_K             | testvector_MAC1_D_6_3_5_M                       | testvector_MAC1_D_6_3_5_T
        "D 6.3.6" | testvector_MAC1_D_6_3_6_K             | testvector_MAC1_D_6_3_6_M                       | testvector_MAC1_D_6_3_6_T
        "D 6.3.7" | testvector_MAC1_D_6_3_7_K             | testvector_MAC1_D_6_3_7_M                       | testvector_MAC1_D_6_3_7_T
    }

    /**
     * D 6.5 KDF2
     */

    static final byte[] testvector_KDF2_D_6_4_1_ss = Hex.decode("96c05619d56c328ab95fe84b18264b08725b85e33fd34f08")
    static final byte[] testvector_KDF2_D_6_4_1_kdp = Hex.decode("")
    static final byte[] testvector_KDF2_D_6_4_1_key = Hex.decode("443024c3dae66b95e6f5670601558f71")
    static final int testvector_KDF2_D_6_4_1_dl = 16

    static final byte[] testvector_KDF2_D_6_4_2_ss = Hex.decode("96f600b73ad6ac5629577eced51743dd2c24c21b1ac83ee4")
    static final byte[] testvector_KDF2_D_6_4_2_kdp = Hex.decode("")
    static final byte[] testvector_KDF2_D_6_4_2_key = Hex.decode("b6295162a7804f5667ba9070f82fa522")
    static final int testvector_KDF2_D_6_4_2_dl = 16

    static final byte[] testvector_KDF2_D_6_4_3_ss = Hex.decode("22518b10e70f2a3f243810ae3254139efbee04aa57c7af7d")
    static final byte[] testvector_KDF2_D_6_4_3_kdp = Hex.decode("75eef81aa3041e33b80971203d2c0c52")
    static final byte[] testvector_KDF2_D_6_4_3_key = Hex.decode("c498af77161cc59f2962b9a713e2b215152d139766ce34a776df11866a69bf2e52a13d9c7c6fc878c50c5ea0bc7b00e0da2447cfd874f6cf92f30d0097111485500c90c3af8b487872d04685d14c8d1dc8d7fa08beb0ce0ababc11f0bd496269142d43525a78e5bc79a17f59676a5706dc54d54d4d1f0bd7e386128ec26afc21")
    static final int testvector_KDF2_D_6_4_3_dl = 128

    static final byte[] testvector_KDF2_D_6_4_4_ss = Hex.decode("7e335afa4b31d772c0635c7b0e06f26fcd781df947d2990a")
    static final byte[] testvector_KDF2_D_6_4_4_kdp = Hex.decode("d65a4812733f8cdbcdfb4b2f4c191d87")
    static final byte[] testvector_KDF2_D_6_4_4_key = Hex.decode("c0bd9e38a8f9de14c2acd35b2f3410c6988cf02400543631e0d6a4c1d030365acbf398115e51aaddebdc9590664210f9aa9fed770d4c57edeafa0b8c14f93300865251218c262d63dadc47dfa0e0284826793985137e0a544ec80abf2fdf5ab90bdaea66204012efe34971dc431d625cd9a329b8217cc8fd0d9f02b13f2f6b0b")
    static final int testvector_KDF2_D_6_4_4_dl = 128

    @Unroll
    def "Verify that IEEE 1609.2 2017 test vectors for section #section KDF2 is correct"(){
        setup:
        def kdf2 = new KDF2BytesGenerator(new SHA256Digest())
        when:
        kdf2.init(new KDFParameters(ss,kdp))
        byte[] dlOut = new byte[expectedDL]
        int res_dl = kdf2.generateBytes(dlOut,0,dlOut.length)
        then:
        res_dl == expectedDL
        Hex.toHexString(dlOut) == Hex.toHexString(expectedKey)

        where:
        section   | ss                                    | kdp                                             | expectedDL                 | expectedKey
        "D 6.4.1" | testvector_KDF2_D_6_4_1_ss            | testvector_KDF2_D_6_4_1_kdp                     | testvector_KDF2_D_6_4_1_dl | testvector_KDF2_D_6_4_1_key
        "D 6.4.2" | testvector_KDF2_D_6_4_2_ss            | testvector_KDF2_D_6_4_2_kdp                     | testvector_KDF2_D_6_4_2_dl | testvector_KDF2_D_6_4_2_key
        "D 6.4.3" | testvector_KDF2_D_6_4_3_ss            | testvector_KDF2_D_6_4_3_kdp                     | testvector_KDF2_D_6_4_3_dl | testvector_KDF2_D_6_4_3_key
        "D 6.4.4" | testvector_KDF2_D_6_4_4_ss            | testvector_KDF2_D_6_4_4_kdp                     | testvector_KDF2_D_6_4_4_dl | testvector_KDF2_D_6_4_4_key
    }


    /**
     * DHC Agreement test from ECC CDH Primitive (SP800-56A Section 5.7.1.2)
     */
    static final String testvector_ECDHC_B_PubKey_x_0 = "700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287"
    static final String testvector_ECDHC_B_PubKey_y_0 = "db71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac"
    static final String testvector_ECDHC_A_PrivKey_0 ="7d7dc5f71eb29ddaf80d6214632eeae03d9058af1fb6d22ed80badb62bc1a534"
    static final String testvector_ECDHC_Z_0 = "46fc62106420ff012e54a434fbdd2d25ccc5852060561e68040dd7778997bd7b"

    static final String testvector_ECDHC_B_PubKey_x_1 = "809f04289c64348c01515eb03d5ce7ac1a8cb9498f5caa50197e58d43a86a7ae"
    static final String testvector_ECDHC_B_PubKey_y_1 = "b29d84e811197f25eba8f5194092cb6ff440e26d4421011372461f579271cda3"
    static final String testvector_ECDHC_A_PrivKey_1 ="38f65d6dce47676044d58ce5139582d568f64bb16098d179dbab07741dd5caf5"
    static final String testvector_ECDHC_Z_1 = "057d636096cb80b67a8c038c890e887d1adfa4195e9b3ce241c8a778c59cda67"

    static final String testvector_ECDHC_B_PubKey_x_2 = "a2339c12d4a03c33546de533268b4ad667debf458b464d77443636440ee7fec3"
    static final String testvector_ECDHC_B_PubKey_y_2 = "ef48a3ab26e20220bcda2c1851076839dae88eae962869a497bf73cb66faf536"
    static final String testvector_ECDHC_A_PrivKey_2 ="1accfaf1b97712b85a6f54b148985a1bdc4c9bec0bd258cad4b3d603f49f32c8"
    static final String testvector_ECDHC_Z_2 = "2d457b78b4614132477618a5b077965ec90730a8c81a1c75d6d4ec68005d67ec"

    static final String testvector_ECDHC_B_PubKey_x_3 = "df3989b9fa55495719b3cf46dccd28b5153f7808191dd518eff0c3cff2b705ed"
    static final String testvector_ECDHC_B_PubKey_y_3 = "422294ff46003429d739a33206c8752552c8ba54a270defc06e221e0feaf6ac4"
    static final String testvector_ECDHC_A_PrivKey_3 ="207c43a79bfee03db6f4b944f53d2fb76cc49ef1c9c4d34d51b6c65c4db6932d"
    static final String testvector_ECDHC_Z_3 = "96441259534b80f6aee3d287a6bb17b5094dd4277d9e294f8fe73e48bf2a0024"

    static final String testvector_ECDHC_B_PubKey_x_4 = "41192d2813e79561e6a1d6f53c8bc1a433a199c835e141b05a74a97b0faeb922"
    static final String testvector_ECDHC_B_PubKey_y_4 = "1af98cc45e98a7e041b01cf35f462b7562281351c8ebf3ffa02e33a0722a1328"
    static final String testvector_ECDHC_A_PrivKey_4 ="59137e38152350b195c9718d39673d519838055ad908dd4757152fd8255c09bf"
    static final String testvector_ECDHC_Z_4 = "19d44c8d63e8e8dd12c22a87b8cd4ece27acdde04dbf47f7f27537a6999a8e62"
    
    static final String testvector_ECDHC_B_PubKey_x_5 = "33e82092a0f1fb38f5649d5867fba28b503172b7035574bf8e5b7100a3052792"
    static final String testvector_ECDHC_B_PubKey_y_5 = "f2cf6b601e0a05945e335550bf648d782f46186c772c0f20d3cd0d6b8ca14b2f"
    static final String testvector_ECDHC_A_PrivKey_5 = "f5f8e0174610a661277979b58ce5c90fee6c9b3bb346a90a7196255e40b132ef"
    static final String testvector_ECDHC_Z_5 = "664e45d5bba4ac931cd65d52017e4be9b19a515f669bea4703542a2c525cd3d3"

    static final String testvector_ECDHC_B_PubKey_x_6 = "6a9e0c3f916e4e315c91147be571686d90464e8bf981d34a90b6353bca6eeba7"
    static final String testvector_ECDHC_B_PubKey_y_6 = "40f9bead39c2f2bcc2602f75b8a73ec7bdffcbcead159d0174c6c4d3c5357f05"
    static final String testvector_ECDHC_A_PrivKey_6 = "3b589af7db03459c23068b64f63f28d3c3c6bc25b5bf76ac05f35482888b5190"
    static final String testvector_ECDHC_Z_6 = "ca342daa50dc09d61be7c196c85e60a80c5cb04931746820be548cdde055679d"

    static final String testvector_ECDHC_B_PubKey_x_7 = "a9c0acade55c2a73ead1a86fb0a9713223c82475791cd0e210b046412ce224bb"
    static final String testvector_ECDHC_B_PubKey_y_7 = "f6de0afa20e93e078467c053d241903edad734c6b403ba758c2b5ff04c9d4229"
    static final String testvector_ECDHC_A_PrivKey_7 = "d8bf929a20ea7436b2461b541a11c80e61d826c0a4c9d322b31dd54e7f58b9c8"
    static final String testvector_ECDHC_Z_7 = "35aa9b52536a461bfde4e85fc756be928c7de97923f0416c7a3ac8f88b3d4489"

    static final String testvector_ECDHC_B_PubKey_x_8 = "94e94f16a98255fff2b9ac0c9598aac35487b3232d3231bd93b7db7df36f9eb9"
    static final String testvector_ECDHC_B_PubKey_y_8 = "d8049a43579cfa90b8093a94416cbefbf93386f15b3f6e190b6e3455fedfe69a"
    static final String testvector_ECDHC_A_PrivKey_8 = "0f9883ba0ef32ee75ded0d8bda39a5146a29f1f2507b3bd458dbea0b2bb05b4d"
    static final String testvector_ECDHC_Z_8 = "605c16178a9bc875dcbff54d63fe00df699c03e8a888e9e94dfbab90b25f39b4"

    static final String testvector_ECDHC_B_PubKey_x_9 = "e099bf2a4d557460b5544430bbf6da11004d127cb5d67f64ab07c94fcdf5274f"
    static final String testvector_ECDHC_B_PubKey_y_9 = "d9c50dbe70d714edb5e221f4e020610eeb6270517e688ca64fb0e98c7ef8c1c5"
    static final String testvector_ECDHC_A_PrivKey_9 = "2beedb04b05c6988f6a67500bb813faf2cae0d580c9253b6339e4a3337bb6c08"
    static final String testvector_ECDHC_Z_9 = "f96e40a1b72840854bb62bc13c40cc2795e373d4e715980b261476835a092e0b"

    static final String testvector_ECDHC_B_PubKey_x_10 = "f75a5fe56bda34f3c1396296626ef012dc07e4825838778a645c8248cff01658"
    static final String testvector_ECDHC_B_PubKey_y_10 = "33bbdf1b1772d8059df568b061f3f1122f28a8d819167c97be448e3dc3fb0c3c"
    static final String testvector_ECDHC_A_PrivKey_10 = "77c15dcf44610e41696bab758943eff1409333e4d5a11bbe72c8f6c395e9f848"
    static final String testvector_ECDHC_Z_10 = "8388fa79c4babdca02a8e8a34f9e43554976e420a4ad273c81b26e4228e9d3a3"

    static final String testvector_ECDHC_B_PubKey_x_11 = "2db4540d50230756158abf61d9835712b6486c74312183ccefcaef2797b7674d"
    static final String testvector_ECDHC_B_PubKey_y_11 = "62f57f314e3f3495dc4e099012f5e0ba71770f9660a1eada54104cdfde77243e"
    static final String testvector_ECDHC_A_PrivKey_11 = "42a83b985011d12303db1a800f2610f74aa71cdf19c67d54ce6c9ed951e9093e"
    static final String testvector_ECDHC_Z_11 = "72877cea33ccc4715038d4bcbdfe0e43f42a9e2c0c3b017fc2370f4b9acbda4a"

    static final String testvector_ECDHC_B_PubKey_x_12 = "cd94fc9497e8990750309e9a8534fd114b0a6e54da89c4796101897041d14ecb"
    static final String testvector_ECDHC_B_PubKey_y_12 = "c3def4b5fe04faee0a11932229fff563637bfdee0e79c6deeaf449f85401c5c4"
    static final String testvector_ECDHC_A_PrivKey_12 = "ceed35507b5c93ead5989119b9ba342cfe38e6e638ba6eea343a55475de2800b"
    static final String testvector_ECDHC_Z_12 = "e4e7408d85ff0e0e9c838003f28cdbd5247cdce31f32f62494b70e5f1bc36307"

    static final String testvector_ECDHC_B_PubKey_x_13 = "15b9e467af4d290c417402e040426fe4cf236bae72baa392ed89780dfccdb471"
    static final String testvector_ECDHC_B_PubKey_y_13 = "cdf4e9170fb904302b8fd93a820ba8cc7ed4efd3a6f2d6b05b80b2ff2aee4e77"
    static final String testvector_ECDHC_A_PrivKey_13 = "43e0e9d95af4dc36483cdd1968d2b7eeb8611fcce77f3a4e7d059ae43e509604"
    static final String testvector_ECDHC_Z_13 = "ed56bcf695b734142c24ecb1fc1bb64d08f175eb243a31f37b3d9bb4407f3b96"

    static final String testvector_ECDHC_B_PubKey_x_14 = "49c503ba6c4fa605182e186b5e81113f075bc11dcfd51c932fb21e951eee2fa1"
    static final String testvector_ECDHC_B_PubKey_y_14 = "8af706ff0922d87b3f0c5e4e31d8b259aeb260a9269643ed520a13bb25da5924"
    static final String testvector_ECDHC_A_PrivKey_14 = "b2f3600df3368ef8a0bb85ab22f41fc0e5f4fdd54be8167a5c3cd4b08db04903"
    static final String testvector_ECDHC_Z_14 = "bc5c7055089fc9d6c89f83c1ea1ada879d9934b2ea28fcf4e4a7e984b28ad2cf"

    static final String testvector_ECDHC_B_PubKey_x_15 = "19b38de39fdd2f70f7091631a4f75d1993740ba9429162c2a45312401636b29c"
    static final String testvector_ECDHC_B_PubKey_y_15 = "09aed7232b28e060941741b6828bcdfa2bc49cc844f3773611504f82a390a5ae"
    static final String testvector_ECDHC_A_PrivKey_15 = "4002534307f8b62a9bf67ff641ddc60fef593b17c3341239e95bdb3e579bfdc8"
    static final String testvector_ECDHC_Z_15 = "9a4e8e657f6b0e097f47954a63c75d74fcba71a30d83651e3e5a91aa7ccd8343"

    static final String testvector_ECDHC_B_PubKey_x_16 = "2c91c61f33adfe9311c942fdbff6ba47020feff416b7bb63cec13faf9b099954"
    static final String testvector_ECDHC_B_PubKey_y_16 = "6cab31b06419e5221fca014fb84ec870622a1b12bab5ae43682aa7ea73ea08d0"
    static final String testvector_ECDHC_A_PrivKey_16 = "4dfa12defc60319021b681b3ff84a10a511958c850939ed45635934ba4979147"
    static final String testvector_ECDHC_Z_16 = "3ca1fc7ad858fb1a6aba232542f3e2a749ffc7203a2374a3f3d3267f1fc97b78"

    static final String testvector_ECDHC_B_PubKey_x_17 = "a28a2edf58025668f724aaf83a50956b7ac1cfbbff79b08c3bf87dfd2828d767"
    static final String testvector_ECDHC_B_PubKey_y_17 = "dfa7bfffd4c766b86abeaf5c99b6e50cb9ccc9d9d00b7ffc7804b0491b67bc03"
    static final String testvector_ECDHC_A_PrivKey_17 = "1331f6d874a4ed3bc4a2c6e9c74331d3039796314beee3b7152fcdba5556304e"
    static final String testvector_ECDHC_Z_17 = "1aaabe7ee6e4a6fa732291202433a237df1b49bc53866bfbe00db96a0f58224f"

    static final String testvector_ECDHC_B_PubKey_x_18 = "a2ef857a081f9d6eb206a81c4cf78a802bdf598ae380c8886ecd85fdc1ed7644"
    static final String testvector_ECDHC_B_PubKey_y_18 = "563c4c20419f07bc17d0539fade1855e34839515b892c0f5d26561f97fa04d1a"
    static final String testvector_ECDHC_A_PrivKey_18 = "dd5e9f70ae740073ca0204df60763fb6036c45709bf4a7bb4e671412fad65da3"
    static final String testvector_ECDHC_Z_18 = "430e6a4fba4449d700d2733e557f66a3bf3d50517c1271b1ddae1161b7ac798c"

    static final String testvector_ECDHC_B_PubKey_x_19 = "ccd8a2d86bc92f2e01bce4d6922cf7fe1626aed044685e95e2eebd464505f01f"
    static final String testvector_ECDHC_B_PubKey_y_19 = "e9ddd583a9635a667777d5b8a8f31b0f79eba12c75023410b54b8567dddc0f38"
    static final String testvector_ECDHC_A_PrivKey_19 = "5ae026cfc060d55600717e55b8a12e116d1d0df34af831979057607c2d9c2f76"
    static final String testvector_ECDHC_Z_19 = "1ce9e6740529499f98d1f1d71329147a33df1d05e4765b539b11cf615d6974d3"

    static final String testvector_ECDHC_B_PubKey_x_20 = "c188ffc8947f7301fb7b53e36746097c2134bf9cc981ba74b4e9c4361f595e4e"
    static final String testvector_ECDHC_B_PubKey_y_20 = "bf7d2f2056e72421ef393f0c0f2b0e00130e3cac4abbcc00286168e85ec55051"
    static final String testvector_ECDHC_A_PrivKey_20 = "b601ac425d5dbf9e1735c5e2d5bdb79ca98b3d5be4a2cfd6f2273f150e064d9d"
    static final String testvector_ECDHC_Z_20 = "4690e3743c07d643f1bc183636ab2a9cb936a60a802113c49bb1b3f2d0661660"

    static final String testvector_ECDHC_B_PubKey_x_21 = "317e1020ff53fccef18bf47bb7f2dd7707fb7b7a7578e04f35b3beed222a0eb6"
    static final String testvector_ECDHC_B_PubKey_y_21 = "09420ce5a19d77c6fe1ee587e6a49fbaf8f280e8df033d75403302e5a27db2ae"
    static final String testvector_ECDHC_A_PrivKey_21 = "fefb1dda1845312b5fce6b81b2be205af2f3a274f5a212f66c0d9fc33d7ae535"
    static final String testvector_ECDHC_Z_21 = "30c2261bd0004e61feda2c16aa5e21ffa8d7e7f7dbf6ec379a43b48e4b36aeb0"

    static final String testvector_ECDHC_B_PubKey_x_22 = "45fb02b2ceb9d7c79d9c2fa93e9c7967c2fa4df5789f9640b24264b1e524fcb1"
    static final String testvector_ECDHC_B_PubKey_y_22 = "5c6e8ecf1f7d3023893b7b1ca1e4d178972ee2a230757ddc564ffe37f5c5a321"
    static final String testvector_ECDHC_A_PrivKey_22 = "334ae0c4693d23935a7e8e043ebbde21e168a7cba3fa507c9be41d7681e049ce"
    static final String testvector_ECDHC_Z_22 = "2adae4a138a239dcd93c243a3803c3e4cf96e37fe14e6a9b717be9599959b11c"

    static final String testvector_ECDHC_B_PubKey_x_23 = "a19ef7bff98ada781842fbfc51a47aff39b5935a1c7d9625c8d323d511c92de6"
    static final String testvector_ECDHC_B_PubKey_y_23 = "e9c184df75c955e02e02e400ffe45f78f339e1afe6d056fb3245f4700ce606ef"
    static final String testvector_ECDHC_A_PrivKey_23 = "2c4bde40214fcc3bfc47d4cf434b629acbe9157f8fd0282540331de7942cf09d"
    static final String testvector_ECDHC_Z_23 = "2e277ec30f5ea07d6ce513149b9479b96e07f4b6913b1b5c11305c1444a1bc0b"

    static final String testvector_ECDHC_B_PubKey_x_24 = "356c5a444c049a52fee0adeb7e5d82ae5aa83030bfff31bbf8ce2096cf161c4b"
    static final String testvector_ECDHC_B_PubKey_y_24 = "57d128de8b2a57a094d1a001e572173f96e8866ae352bf29cddaf92fc85b2f92"
    static final String testvector_ECDHC_A_PrivKey_24 = "85a268f9d7772f990c36b42b0a331adc92b5941de0b862d5d89a347cbf8faab0"
    static final String testvector_ECDHC_Z_24 = "1e51373bd2c6044c129c436e742a55be2a668a85ae08441b6756445df5493857"


    @Unroll
    def "Verify ECDHC Agreement Function from ECC CDH Primitive for test vector #vector"(){
        setup:
        ECParameterSpec ecNistP256Spec = ECNamedCurveTable.getParameterSpec("P-256")
        ECDomainParameters domainParameters = new ECDomainParameters(ecNistP256Spec.getCurve(),
                ecNistP256Spec.getG(), ecNistP256Spec.getN())
        ECDHCBasicAgreement agreement = new ECDHCBasicAgreement()
        ECPrivateKeyParameters aPriv = new ECPrivateKeyParameters(new BigInteger(a_priv, 16),domainParameters)
        ECPoint bPoint = ecNistP256Spec.getCurve().createPoint(new BigInteger(B_pub_x,16),new BigInteger(B_pub_y,16))
        ECPublicKeyParameters bPub = new ECPublicKeyParameters(bPoint,domainParameters)
        agreement.init(aPriv)
        when:
        def z = agreement.calculateAgreement(bPub)
        byte[] Z = BigIntegers.asUnsignedByteArray(agreement.getFieldSize(), z)
        then:
        Hex.toHexString(Z) == expectedZ
        where:
        vector  | B_pub_x                       | B_pub_y                         | a_priv                        | expectedZ
        "0"     | testvector_ECDHC_B_PubKey_x_0 |  testvector_ECDHC_B_PubKey_y_0  | testvector_ECDHC_A_PrivKey_0  | testvector_ECDHC_Z_0
        "1"     | testvector_ECDHC_B_PubKey_x_1 |  testvector_ECDHC_B_PubKey_y_1  | testvector_ECDHC_A_PrivKey_1  | testvector_ECDHC_Z_1
        "2"     | testvector_ECDHC_B_PubKey_x_2 |  testvector_ECDHC_B_PubKey_y_2  | testvector_ECDHC_A_PrivKey_2  | testvector_ECDHC_Z_2
        "3"     | testvector_ECDHC_B_PubKey_x_3 |  testvector_ECDHC_B_PubKey_y_3  | testvector_ECDHC_A_PrivKey_3  | testvector_ECDHC_Z_3
        "4"     | testvector_ECDHC_B_PubKey_x_4 |  testvector_ECDHC_B_PubKey_y_4  | testvector_ECDHC_A_PrivKey_4  | testvector_ECDHC_Z_4
        "5"     | testvector_ECDHC_B_PubKey_x_5 |  testvector_ECDHC_B_PubKey_y_5  | testvector_ECDHC_A_PrivKey_5  | testvector_ECDHC_Z_5
        "6"     | testvector_ECDHC_B_PubKey_x_6 |  testvector_ECDHC_B_PubKey_y_6  | testvector_ECDHC_A_PrivKey_6  | testvector_ECDHC_Z_6
        "7"     | testvector_ECDHC_B_PubKey_x_7 |  testvector_ECDHC_B_PubKey_y_7  | testvector_ECDHC_A_PrivKey_7  | testvector_ECDHC_Z_7
        "8"     | testvector_ECDHC_B_PubKey_x_8 |  testvector_ECDHC_B_PubKey_y_8  | testvector_ECDHC_A_PrivKey_8  | testvector_ECDHC_Z_8
        "9"     | testvector_ECDHC_B_PubKey_x_9 |  testvector_ECDHC_B_PubKey_y_9  | testvector_ECDHC_A_PrivKey_9  | testvector_ECDHC_Z_9
        "10"    | testvector_ECDHC_B_PubKey_x_10|  testvector_ECDHC_B_PubKey_y_10 | testvector_ECDHC_A_PrivKey_10 | testvector_ECDHC_Z_10
        "11"    | testvector_ECDHC_B_PubKey_x_11|  testvector_ECDHC_B_PubKey_y_11 | testvector_ECDHC_A_PrivKey_11 | testvector_ECDHC_Z_11
        "12"    | testvector_ECDHC_B_PubKey_x_12|  testvector_ECDHC_B_PubKey_y_12 | testvector_ECDHC_A_PrivKey_12 | testvector_ECDHC_Z_12
        "13"    | testvector_ECDHC_B_PubKey_x_13|  testvector_ECDHC_B_PubKey_y_13 | testvector_ECDHC_A_PrivKey_13 | testvector_ECDHC_Z_13
        "14"    | testvector_ECDHC_B_PubKey_x_14|  testvector_ECDHC_B_PubKey_y_14 | testvector_ECDHC_A_PrivKey_14 | testvector_ECDHC_Z_14
        "15"    | testvector_ECDHC_B_PubKey_x_15|  testvector_ECDHC_B_PubKey_y_15 | testvector_ECDHC_A_PrivKey_15 | testvector_ECDHC_Z_15
        "16"    | testvector_ECDHC_B_PubKey_x_16|  testvector_ECDHC_B_PubKey_y_16 | testvector_ECDHC_A_PrivKey_16 | testvector_ECDHC_Z_16
        "17"    | testvector_ECDHC_B_PubKey_x_17|  testvector_ECDHC_B_PubKey_y_17 | testvector_ECDHC_A_PrivKey_17 | testvector_ECDHC_Z_17
        "18"    | testvector_ECDHC_B_PubKey_x_18|  testvector_ECDHC_B_PubKey_y_18 | testvector_ECDHC_A_PrivKey_18 | testvector_ECDHC_Z_18
        "19"    | testvector_ECDHC_B_PubKey_x_19|  testvector_ECDHC_B_PubKey_y_19 | testvector_ECDHC_A_PrivKey_19 | testvector_ECDHC_Z_19
        "20"    | testvector_ECDHC_B_PubKey_x_20|  testvector_ECDHC_B_PubKey_y_20 | testvector_ECDHC_A_PrivKey_20 | testvector_ECDHC_Z_20
        "21"    | testvector_ECDHC_B_PubKey_x_21|  testvector_ECDHC_B_PubKey_y_21 | testvector_ECDHC_A_PrivKey_21 | testvector_ECDHC_Z_21
        "22"    | testvector_ECDHC_B_PubKey_x_22|  testvector_ECDHC_B_PubKey_y_22 | testvector_ECDHC_A_PrivKey_22 | testvector_ECDHC_Z_22
        "23"    | testvector_ECDHC_B_PubKey_x_23|  testvector_ECDHC_B_PubKey_y_23 | testvector_ECDHC_A_PrivKey_23 | testvector_ECDHC_Z_23
        "24"    | testvector_ECDHC_B_PubKey_x_24|  testvector_ECDHC_B_PubKey_y_24 | testvector_ECDHC_A_PrivKey_24 | testvector_ECDHC_Z_24

    }

}
