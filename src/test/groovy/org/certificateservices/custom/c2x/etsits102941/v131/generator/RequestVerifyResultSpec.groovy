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
package org.certificateservices.custom.c2x.etsits102941.v131.generator

import org.bouncycastle.util.encoders.Hex
import org.certificateservices.custom.c2x.common.BaseStructSpec
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.authorization.InnerAtRequest
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.authorization.InnerAtRequestSpec
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.authorization.SharedAtRequest
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.EcSignature
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.PublicKeys
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Psid
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.HeaderInfo
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.SignerIdentifier
import org.certificateservices.custom.c2x.ieee1609dot2.generator.receiver.Receiver
import spock.lang.Specification

import javax.crypto.SecretKey

/**
 * Unit tests for RequestVerifyResult
 *
 * @author Philip Vendil, p.vendil@cgi.com
 */
class RequestVerifyResultSpec extends BaseStructSpec {

    InnerAtRequest innerAtRequest = genInnerAtRequest()
    byte[] requestHash = Hex.decode("01020304050607080910111213141516")


    def "Verify constructor and getters"(){
        when:
        def ard = new RequestVerifyResult<InnerAtRequest>(Signature.SignatureChoices.ecdsaNistP256Signature,new SignerIdentifier(), new HeaderInfo(),innerAtRequest,requestHash, Mock(SecretKey), Mock(Receiver))
        then:
        ard.getSignAlg() == Signature.SignatureChoices.ecdsaNistP256Signature
        ard.getSignerIdentifier() != null
        ard.getHeaderInfo() != null
        ard.getValue() == innerAtRequest
        ard.getRequestHash() == requestHash
        ard.getSecretKey() != null

    }

    def "Verify toString()"(){
        setup:
        HeaderInfo hi = new HeaderInfo(new Psid(1),null,null,null,null,null,null,null,null)
        expect:
        println new RequestVerifyResult<InnerAtRequest>(Signature.SignatureChoices.ecdsaNistP256Signature,new SignerIdentifier(), hi,innerAtRequest,requestHash, Mock(SecretKey), Mock(Receiver)).toString()
        new RequestVerifyResult<InnerAtRequest>(Signature.SignatureChoices.ecdsaNistP256Signature,new SignerIdentifier(), hi,innerAtRequest,requestHash, Mock(SecretKey), Mock(Receiver)).toString() == """RequestVerifyResult [
  signAlg=ecdsaNistP256Signature,
  signerIdentifier=SignerIdentifier [self],
  headerInfo=HeaderInfo [
    psid=[1(1)]
  ],
  value=InnerAtRequest [
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
  ]
  receiver=EXISTS,
  secretKey=EXISTS,
  requestHash=01020304050607080910111213141516,
]"""
    }



    private def genInnerAtRequest(){
        PublicKeys publicKeys = InnerAtRequestSpec.genPublicKeys()
        byte[] hmacKey = Hex.decode("0011223344556677889900112233445566778899001122334455667788990011")
        SharedAtRequest sharedAtRequest = InnerAtRequestSpec.genSharedAtRequest()
        EcSignature ecSignature = InnerAtRequestSpec.genEcSignature()

        return new InnerAtRequest(publicKeys, hmacKey, sharedAtRequest, ecSignature)
    }
}
