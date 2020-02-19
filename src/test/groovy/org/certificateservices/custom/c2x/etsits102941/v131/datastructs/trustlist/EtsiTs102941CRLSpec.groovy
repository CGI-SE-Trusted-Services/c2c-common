package org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist

import org.bouncycastle.util.encoders.Hex
import org.certificateservices.custom.c2x.common.BaseStructSpec
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.secureddata.EtsiTs103097DataSignedSpec
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.Ieee1609Dot2Data

import static org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.Ieee1609Dot2Content.Ieee1609Dot2ContentChoices.signedData

/**
 * Unit tests for EtsiTs102941CTL and EtsiTs102941BaseList
 */
class EtsiTs102941CRLSpec extends BaseStructSpec {


    byte[] cRLData = Hex.decode("0381004003801f01840001011c9ae5291c9c36a90102112233445566778811223344556677994002026f0001cea794e140688101018003008100198108736f6d654e616d6500000000001c105b1886002301028002026e80010180020270800201380101e081010301ffc00080834432b902105adda438533a3dbc9c164df3641dee19c0b666ca01fad357d588ad8080834432b902105adda438533a3dbc9c164df3641dee19c0b666ca01fad357d588ad8080de5c0c3ea36dd7303eb0a855231d7b30985815cf8df89f22b145ce380d77a948169e3783e59901b9d54edf136b15616feeac3f84c181c8368fd43b2c9df2fb02808015c890adea41aec058663f244856c8b4e74f192bb1dc1b29f859f1b1f417abdf326299cdaf7ad81f19ef3b847959cb621a1cc48a93620a49f59e52762d5ab1f7")

    def "Verify that constructor accepts valid signed data same as EtsiTs103097DataSigned"(){
        setup:
        def sd = EtsiTs103097DataSignedSpec.newSignedData()
        when:
        def d = new EtsiTs102941CRL(2, sd)
        then:
        serializeToHex(d) == "0281004003800801020304050607084001640000000000989680810101800300810079810a536f6d6543657274496431323301b016a58f24840005830101800009620102800165801e0000000000000000000000000000000000000000000000000000000000f58001ca801e0000000000000000000000000000000000000000000000000000000000f501022081c0e0810102010340008084000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000df808084000000000000000000000000000000000000000000000000000000000000014300000000000000000000000000000000000000000000000000000000000001a78080000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000f58080000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000f5"
        when:
        def d2 = new EtsiTs102941CRL(Hex.decode("0281004003800801020304050607084001640000000000989680810101800300810079810a536f6d6543657274496431323301b016a58f24840005830101800009620102800165801e0000000000000000000000000000000000000000000000000000000000f58001ca801e0000000000000000000000000000000000000000000000000000000000f501022081c0e0810102010340008084000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000df808084000000000000000000000000000000000000000000000000000000000000014300000000000000000000000000000000000000000000000000000000000001a78080000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000f58080000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000f5"))
        then:
        d2.getProtocolVersion() == 2
        d2.getContent().getType() == signedData

        when:
        def d3 = new EtsiTs102941CRL(sd)
        then:
        d3.protocolVersion == Ieee1609Dot2Data.DEFAULT_VERSION
        d3.content == sd

    }

    def "Verify that toString returns a prettified CRL"(){
        expect:
        new EtsiTs102941CRL(cRLData).toString() == """EtsiTs103097DataSigned [
  protocolVersion=3,
  content=[
    signedData=[
      hashAlgorithm=sha256,
      tbsData=[
        payload=[
          data=[
            protocolVersion=3,
            content=[
              EtsiTs102941Data [
                version=1
                content=[certificateRevocationList=[
                    version=1
                    thisUpdate=Time32 [timeStamp=Sun Mar 17 14:14:14 CET 2019 (479913257)]
                    nextUpdate=Time32 [timeStamp=Mon Mar 18 14:14:14 CET 2019 (479999657)]
                    entries=
                      [1122334455667788]
                      [1122334455667799]
                  ]
                ]
              ]
            ]
          ]
        ],
        headerInfo=[
          psid=[623(26f)],
          generationTime=[timeStamp=Thu Feb 13 16:55:26 CET 2020 (508694129361000)]
        ]
      ],
      signer=[certificate=[
      EtsiTs103097Certificate [
        version=3
        type=explicit
        issuer=[self=sha256]
        toBeSigned=[
          id=[name=[someName]]
          cracaId=[000000]
          crlSeries=[0]
          validityPeriod=[start=Time32 [timeStamp=Sun Dec 02 12:12:21 CET 2018 (470833944)], duration=Duration [35 years]]
          region=NONE
          assuranceLevel=NONE
          appPermissions=[[psid=[622(26e)], ssp=[opaque=[01]]],[psid=[624(270)], ssp=[opaque=[0138]]]]
          certIssuePermissions=[[subjectPermissions=[all], minChainDepth=3, chainDepthRange=-1, eeType=[app=true, enroll=true]]]
          certRequestPermissions=NONE
          canRequestRollover=false
          encryptionKey=[supportedSymmAlg=aes128Ccm, publicKey=[ecdsaNistP256=[compressedy1=4432b902105adda438533a3dbc9c164df3641dee19c0b666ca01fad357d588ad]]]
          verifyKeyIndicator=[verificationKey=[ecdsaNistP256=[compressedy1=4432b902105adda438533a3dbc9c164df3641dee19c0b666ca01fad357d588ad]]]
        ]
        signature=[ecdsaNistP256Signature=EcdsaP256[r=[xonly=de5c0c3ea36dd7303eb0a855231d7b30985815cf8df89f22b145ce380d77a948], s=169e3783e59901b9d54edf136b15616feeac3f84c181c8368fd43b2c9df2fb02]]
      ]]],
      signature=[ecdsaNistP256Signature=EcdsaP256[r=[xonly=15c890adea41aec058663f244856c8b4e74f192bb1dc1b29f859f1b1f417abdf], s=326299cdaf7ad81f19ef3b847959cb621a1cc48a93620a49f59e52762d5ab1f7]]
    ]
  ]
]
"""
    }

}
