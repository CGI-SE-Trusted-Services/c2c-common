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
package org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes

import org.certificateservices.custom.c2x.common.BaseStructSpec
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.secureddata.EtsiTs103097DataEncrypted
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.secureddata.EtsiTs103097DataSignedExternalPayload
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.secureddata.EtsiTs103097DataSpec
import spock.lang.Shared
import spock.lang.Unroll

import static org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.EcSignature.EcSignatureChoices.ecSignature
import static org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.EcSignature.EcSignatureChoices.encryptedEcSignature

/**
 * Unit tests for EcSignature
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class EcSignatureSpec extends BaseStructSpec {

    @Shared EtsiTs103097DataEncrypted encryptedValue = new EtsiTs103097DataEncrypted(2, EtsiTs103097DataSpec.genEncryptedData())
    @Shared EtsiTs103097DataSignedExternalPayload signedExternalPayloadValue = new EtsiTs103097DataSignedExternalPayload(2, EtsiTs103097DataSpec.genSignedData())

    @Unroll
    def "Verify that EcSignature is correctly encoded for type #choice"(){
        when:
        def id = new EcSignature(value)

        then:
        serializeToHex(id) == encoding

        when:
        EcSignature id2 = deserializeFromHex(new EcSignature(), encoding)

        then:

        id2.choice == choice
        id2.type == choice
        if(id2.type == encryptedEcSignature){
            assert id2.getEncryptedEcSignature() == value
        }else{
            assert  id2.getEcSignature() != null // Cannot be equal due to  EtsiTs103097Certificate becomes Certificate after serialization.
        }
        !choice.extension

        where:
        choice                      | value                      | encoding
        encryptedEcSignature        | encryptedValue             | "80028201018201020304050607088080000000000000000000000000000000000000000000000000000000000000007b000000000000000000000000000000f5000000000000000000000000000001d3800102030405060708091011120411121314"
        ecSignature                 | signedExternalPayloadValue | "81028100208001020304050607080910111213141516171819202122232425262728293031324001640000000000002710810101800300810079810a536f6d6543657274496431323301b016a58f24840005830101800009620102800165801e0000000000000000000000000000000000000000000000000000000000f58001ca801e0000000000000000000000000000000000000000000000000000000000f501022081c0e0810102010340008084000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000df808084000000000000000000000000000000000000000000000000000000000000014300000000000000000000000000000000000000000000000000000000000001a78080000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000f58080000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000f5"
    }

    def "Verify toString"(){
        expect:
        new EcSignature(encryptedValue).toString() == expectedEncryptedValueString
        new EcSignature(signedExternalPayloadValue).toString() == expectedSignedExternalPayloadValue
    }


    def expectedEncryptedValueString = """EcSignature [encryptedEcSignature=EtsiTs103097Data [
    protocolVersion=2,
    content=[
      encryptedData=[
        recipients=[[certRecipInfo=[recipientId=[0102030405060708], encKey=[eciesNistP256=[v=[xonly=000000000000000000000000000000000000000000000000000000000000007b], s=000000000000000000000000000000f5, t=000000000000000000000000000001d3]]]]],
        ciphertext=[aes128ccm=[nounce=010203040506070809101112, ccmCipherText=11121314]]
      ]
    ]
  ]
]"""

    def expectedSignedExternalPayloadValue = """EcSignature [ecSignature=EtsiTs103097Data [
    protocolVersion=2,
    content=[
      signedData=[
        hashAlgorithm=sha256,
        tbsData=[
          payload=[
            extDataHash=[sha256HashedData=0102030405060708091011121314151617181920212223242526272829303132]
          ],
          headerInfo=[
            psid=[100(64)],
            generationTime=[timeStamp=Thu Jan 01 01:00:10 CET 2004 (10000)]
          ]
        ],
        signer=[certificate=[
        EtsiTs103097Certificate [
          version=3
          type=explicit
          issuer=[self=sha256]
          toBeSigned=[
            id=[name=[SomeCertId]]
            cracaId=[313233]
            crlSeries=[432]
            validityPeriod=[start=Time32 [timeStamp=Fri Jan 15 14:20:33 CET 2016 (379948836)], duration=Duration [5 hours]]
            region=[SequenceOfIdentifiedRegion [[CountryOnly [9]]]]
            assuranceLevel=[subjectAssurance=98 (assuranceLevel=3, confidenceLevel= 2 )]
            appPermissions=[[psid=[101(65)], ssp=[opaque=[0000000000000000000000000000000000000000000000000000000000f5]]],[psid=[202(ca)], ssp=[opaque=[0000000000000000000000000000000000000000000000000000000000f5]]]]
            certIssuePermissions=[[subjectPermissions=[all], minChainDepth=1, chainDepthRange=0, eeType=[app=true, enroll=true]],[subjectPermissions=[all], minChainDepth=2, chainDepthRange=3, eeType=[app=false, enroll=true]]]
            certRequestPermissions=NONE
            canRequestRollover=false
            encryptionKey=[supportedSymmAlg=aes128Ccm, publicKey=[ecdsaNistP256=[uncompressed=[x=000000000000000000000000000000000000000000000000000000000000007b, y=00000000000000000000000000000000000000000000000000000000000000df]]]]
            verifyKeyIndicator=[verificationKey=[ecdsaNistP256=[uncompressed=[x=0000000000000000000000000000000000000000000000000000000000000143, y=00000000000000000000000000000000000000000000000000000000000001a7]]]]
          ]
          signature=[ecdsaNistP256Signature=EcdsaP256[r=[xonly=000000000000000000000000000000000000000000000000000000000000007b], s=00000000000000000000000000000000000000000000000000000000000000f5]]
        ]]],
        signature=[ecdsaNistP256Signature=EcdsaP256[r=[xonly=000000000000000000000000000000000000000000000000000000000000007b], s=00000000000000000000000000000000000000000000000000000000000000f5]]
      ]
    ]
  ]
]"""
}
