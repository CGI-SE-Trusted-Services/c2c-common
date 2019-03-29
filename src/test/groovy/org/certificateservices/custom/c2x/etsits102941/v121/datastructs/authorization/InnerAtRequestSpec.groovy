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
package org.certificateservices.custom.c2x.etsits102941.v121.datastructs.authorization

import org.bouncycastle.util.encoders.Hex
import org.certificateservices.custom.c2x.common.BaseStructSpec
import org.certificateservices.custom.c2x.etsits102941.v121.datastructs.basetypes.CertificateFormat
import org.certificateservices.custom.c2x.etsits102941.v121.datastructs.basetypes.CertificateSubjectAttributes
import org.certificateservices.custom.c2x.etsits102941.v121.datastructs.basetypes.EcSignature
import org.certificateservices.custom.c2x.etsits102941.v121.datastructs.basetypes.PublicKeys
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.secureddata.EtsiTs103097DataEncrypted
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.secureddata.EtsiTs103097DataSpec
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.*
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.CertificateId

/**
 * Unit tests for InnerAtRequest
 *
 * @author Philip Vendil, p.vendil@cgi.com
 */
class InnerAtRequestSpec extends BaseStructSpec {

    PublicKeys publicKeys = genPublicKeys()
    byte[] hmacKey = Hex.decode("0011223344556677889900112233445566778899001122334455667788990011")
    SharedAtRequest sharedAtRequest = genSharedAtRequest()
    EcSignature ecSignature = genEcSignature()

    def "Verify that constructor and getters are correct and it is correctly encoded"(){
        when:
        InnerAtRequest r = new InnerAtRequest(publicKeys, hmacKey, sharedAtRequest, ecSignature)
        then:
        serializeToHex(r) == "00808084000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000df008080000000000000000000000000000000000000000000000000000000000000007b001122334455667788990011223344556677889900112233445566778899001100001122334455667700112233445566778899001122334455017c810a536f6d6543657274496416a58f24840005830101800009620102800165801e0000000000000000000000000000000000000000000000000000000000f58001ca801e0000000000000000000000000000000000000000000000000000000000f580028201018201020304050607088080000000000000000000000000000000000000000000000000000000000000007b000000000000000000000000000000f5000000000000000000000000000001d3800102030405060708091011120411121314"
        when:
        InnerAtRequest r2 = deserializeFromHex(new InnerAtRequest(), "00808084000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000df008080000000000000000000000000000000000000000000000000000000000000007b001122334455667788990011223344556677889900112233445566778899001100001122334455667700112233445566778899001122334455017c810a536f6d6543657274496416a58f24840005830101800009620102800165801e0000000000000000000000000000000000000000000000000000000000f58001ca801e0000000000000000000000000000000000000000000000000000000000f580028201018201020304050607088080000000000000000000000000000000000000000000000000000000000000007b000000000000000000000000000000f5000000000000000000000000000001d3800102030405060708091011120411121314")
        then:
        r2.getPublicKeys() == publicKeys
        r2.getHmacKey() == hmacKey
        r2.getSharedAtRequest() == sharedAtRequest
        r2.getEcSignature() == ecSignature
    }

    def "Verify toString()"(){
        expect:
        new InnerAtRequest(publicKeys, hmacKey, sharedAtRequest, ecSignature).toString() == """InnerAtRequest [
  publicKeys=[verificationKey=[ecdsaNistP256=[uncompressed=[x=000000000000000000000000000000000000000000000000000000000000007b, y=00000000000000000000000000000000000000000000000000000000000000df]]],encryptionKey=[supportedSymmAlg=aes128Ccm, publicKey=[ecdsaNistP256=[xonly=000000000000000000000000000000000000000000000000000000000000007b]]]]
  hmacKey=0011223344556677889900112233445566778899001122334455667788990011
  sharedAtRequest=[
    eaId=[0011223344556677]
    keyTag=00112233445566778899001122334455
    certificateFormat=COERInteger [value=1]
    requestedSubjectAttributes=[
      id=[name=[SomeCertId]]
      validityPeriod=[start=Time32 [timeStamp=Fri Jan 15 14:20:33 CET 2016 (379948836)], duration=Duration [5 hours]]
      region=[SequenceOfIdentifiedRegion [[CountryOnly [9]]]]
      assuranceLevel=[subjectAssurance=98 (assuranceLevel=3, confidenceLevel= 2 )]
      appPermissions=[[psid=[101(65)], ssp=[opaque=[0000000000000000000000000000000000000000000000000000000000f5]]],[psid=[202(ca)], ssp=[opaque=[0000000000000000000000000000000000000000000000000000000000f5]]]]
      certIssuePermissions=NONE
    ]
  ]
  ecSignature=[encryptedEcSignature=EtsiTs103097Data [
      protocolVersion=2,
      content=[
        encryptedData=[
          recipients=[[certRecipInfo=[recipientId=[0102030405060708], encKey=[eciesNistP256=[v=[xonly=000000000000000000000000000000000000000000000000000000000000007b], s=000000000000000000000000000000f5, t=000000000000000000000000000001d3]]]]],
          ciphertext=[aes128ccm=[nounce=010203040506070809101112, ccmCipherText=11121314]]
        ]
      ]
    ]
  ]
]"""
    }

    static SharedAtRequest genSharedAtRequest(){
        HashedId8 eaId = new HashedId8(Hex.decode("0011223344556677"))
        byte[] keyTag = Hex.decode("00112233445566778899001122334455")
        CertificateSubjectAttributes requestedSubjectAttributes = SharedAtRequestSpec.genCertificateSubjectAttributes()
        return new SharedAtRequest(eaId,keyTag, CertificateFormat.TS103097C131,requestedSubjectAttributes);
        CertificateId id = new CertificateId(new Hostname("SomeCertId"))
    }

    static PublicKeys genPublicKeys(){
        EccP256CurvePoint r_256 = new EccP256CurvePoint(new BigInteger(123),new BigInteger(223))
        PublicVerificationKey verificationKey = new PublicVerificationKey(PublicVerificationKey.PublicVerificationKeyChoices.ecdsaNistP256, r_256)

        EccP256CurvePoint p = new EccP256CurvePoint(new BigInteger(123))
        BasePublicEncryptionKey pubKey = new BasePublicEncryptionKey(BasePublicEncryptionKey.BasePublicEncryptionKeyChoices.ecdsaNistP256, p)
        PublicEncryptionKey encryptionKey = new PublicEncryptionKey(SymmAlgorithm.aes128Ccm,pubKey)
        return new PublicKeys(verificationKey,encryptionKey)
    }

    static EcSignature genEcSignature(){
        EtsiTs103097DataEncrypted encryptedValue = new EtsiTs103097DataEncrypted(2, EtsiTs103097DataSpec.genEncryptedData())
        return new EcSignature(encryptedValue)
    }
}
