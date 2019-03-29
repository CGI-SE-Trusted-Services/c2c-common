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
package org.certificateservices.custom.c2x.etsits102941.v121.datastructs.messagesca

import org.bouncycastle.util.encoders.Hex
import org.certificateservices.custom.c2x.common.BaseStructSpec
import org.certificateservices.custom.c2x.etsits102941.v121.datastructs.authorization.InnerAtRequestSpec
import org.certificateservices.custom.c2x.etsits102941.v121.datastructs.authorization.SharedAtRequestSpec
import org.certificateservices.custom.c2x.etsits102941.v121.datastructs.basetypes.Version
import org.certificateservices.custom.c2x.etsits102941.v121.datastructs.camanagement.CaCertificateRequest
import org.certificateservices.custom.c2x.etsits102941.v121.datastructs.enrollment.InnerEcRequestSignedForPop
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.secureddata.EtsiTs103097DataSignedSpec


/**
 * Unit tests for EtsiTs102941Data
 *
 * @author Philip Vendil, p.vendil@cgi.com
 */
class EtsiTs102941DataSpec extends BaseStructSpec {

    def content = new EtsiTs102941DataContent(new InnerEcRequestSignedForPop(EtsiTs103097DataSignedSpec.newSignedData()))
    def content3 = new EtsiTs102941DataContent(new CaCertificateRequest(InnerAtRequestSpec.genPublicKeys(), SharedAtRequestSpec.genCertificateSubjectAttributes()))

    def "Verify that constructor and getters are correct and it is correctly encoded"(){
        when:

        EtsiTs102941Data d = new EtsiTs102941Data(Version.V1,content)
        then:

        Hex.toHexString(d.encoded) == "0101800381004003800801020304050607084001640000000000002710810101800300810079810a536f6d6543657274496431323301b016a58f24840005830101800009620102800165801e0000000000000000000000000000000000000000000000000000000000f58001ca801e0000000000000000000000000000000000000000000000000000000000f501022081c0e0810102010340008084000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000df808084000000000000000000000000000000000000000000000000000000000000014300000000000000000000000000000000000000000000000000000000000001a78080000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000f58080000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000f5"
        when:
        EtsiTs102941Data d2 = deserializeFromHex(new EtsiTs102941Data(), "0101800381004003800801020304050607084001640000000000002710810101800300810079810a536f6d6543657274496431323301b016a58f24840005830101800009620102800165801e0000000000000000000000000000000000000000000000000000000000f58001ca801e0000000000000000000000000000000000000000000000000000000000f501022081c0e0810102010340008084000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000df808084000000000000000000000000000000000000000000000000000000000000014300000000000000000000000000000000000000000000000000000000000001a78080000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000f58080000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000f5")
        then:
        d2.version == Version.V1
        d2.content.toString() == content.toString()

        when:

        EtsiTs102941Data d3 = new EtsiTs102941Data(Version.V1,content3)
        then:

        Hex.toHexString(d3.encoded) == "01018900808084000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000df008080000000000000000000000000000000000000000000000000000000000000007b7c810a536f6d6543657274496416a58f24840005830101800009620102800165801e0000000000000000000000000000000000000000000000000000000000f58001ca801e0000000000000000000000000000000000000000000000000000000000f5"
        when:
        EtsiTs102941Data d4 = new EtsiTs102941Data(Hex.decode("01018900808084000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000df008080000000000000000000000000000000000000000000000000000000000000007b7c810a536f6d6543657274496416a58f24840005830101800009620102800165801e0000000000000000000000000000000000000000000000000000000000f58001ca801e0000000000000000000000000000000000000000000000000000000000f5"))
        then:
        d4.version == Version.V1
        d4.content.toString() == content3.toString()
    }

    def "Verify toString"(){
        expect:
        new EtsiTs102941Data(Version.V1,content).toString() == """EtsiTs102941Data [
  version=1
  content=[enrolmentRequest=[
      protocolVersion=3,
      content=[
        signedData=[
          hashAlgorithm=sha256,
          tbsData=[
            payload=[
              data=[
                protocolVersion=3,
                content=[
                  unsecuredData=[data=0102030405060708]
                ]
              ]
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
  ]
]"""
    }
}
