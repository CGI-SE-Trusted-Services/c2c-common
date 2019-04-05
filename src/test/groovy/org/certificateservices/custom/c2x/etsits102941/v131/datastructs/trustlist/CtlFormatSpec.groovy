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
package org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist

import org.bouncycastle.util.encoders.Hex
import org.certificateservices.custom.c2x.common.BaseStructSpec
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.Version
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.SingleEtsiTs103097CertificateSpec
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId8
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Time32

import java.text.SimpleDateFormat

/**
 * Unit tests for CtlFormat
 *
 * @author Philip Vendil, p.vendil@cgi.com
 */
class CtlFormatSpec extends BaseStructSpec {

    SimpleDateFormat dateFormat = new SimpleDateFormat("yyyyMMdd HH:mm:ss")
    Version ver = Version.V1
    Time32 nextUpdate = new Time32(dateFormat.parse("20190318 14:14:14"))
    RootCaEntry rootCaEntry = new RootCaEntry(SingleEtsiTs103097CertificateSpec.genCert(),null)
    CtlCommand addCommand = new CtlCommand(new CtlEntry(rootCaEntry))
    HashedId8 certValue = new HashedId8(Hex.decode("001122334455667788"))
    CtlDelete ctlDelete = new CtlDelete(certValue)
    CtlCommand delCommand = new CtlCommand(ctlDelete)
    CtlCommand[] ctlCommands =  [addCommand,delCommand] as CtlCommand[]

    def "Verify that constructor and getters are correct and it is correctly encoded"(){
        when:
        CtlFormat f1 = new CtlFormat(ver,nextUpdate,false,12,ctlCommands)
        then:
        serializeToHex(f1) == "0001011c9c36a9000c0102808000800300810079810a536f6d6543657274496431323301b016a58f24840005830101800009620102800165801e0000000000000000000000000000000000000000000000000000000000f58001ca801e0000000000000000000000000000000000000000000000000000000000f501022081c0e0810102010340008084000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000df808084000000000000000000000000000000000000000000000000000000000000014300000000000000000000000000000000000000000000000000000000000001a78080000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000f581801122334455667788"
        when:
        CtlFormat f2 = deserializeFromHex(new CtlFormat(), "0001011c9c36a9000c0102808000800300810079810a536f6d6543657274496431323301b016a58f24840005830101800009620102800165801e0000000000000000000000000000000000000000000000000000000000f58001ca801e0000000000000000000000000000000000000000000000000000000000f501022081c0e0810102010340008084000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000df808084000000000000000000000000000000000000000000000000000000000000014300000000000000000000000000000000000000000000000000000000000001a78080000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000f581801122334455667788")
        then:
        f2.getVersion() == ver
        f2.getNextUpdate() == nextUpdate
        !f2.isFullCtl()
        f2.getCtlSequence() == 12
        f2.getCtlCommands() == ctlCommands
        when:
        CtlFormat f3 = new CtlFormat(ver,nextUpdate,true,12,[addCommand] as CtlCommand[])
        then:
        serializeToHex(f3) == "0001011c9c36a9ff0c0101808000800300810079810a536f6d6543657274496431323301b016a58f24840005830101800009620102800165801e0000000000000000000000000000000000000000000000000000000000f58001ca801e0000000000000000000000000000000000000000000000000000000000f501022081c0e0810102010340008084000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000df808084000000000000000000000000000000000000000000000000000000000000014300000000000000000000000000000000000000000000000000000000000001a78080000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000f5"
        when:
        CtlFormat f4 = deserializeFromHex(new CtlFormat(), "0001011c9c36a9ff0c0101808000800300810079810a536f6d6543657274496431323301b016a58f24840005830101800009620102800165801e0000000000000000000000000000000000000000000000000000000000f58001ca801e0000000000000000000000000000000000000000000000000000000000f501022081c0e0810102010340008084000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000df808084000000000000000000000000000000000000000000000000000000000000014300000000000000000000000000000000000000000000000000000000000001a78080000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000f5")
        then:
        f4.isFullCtl()
    }

    def "Verify that CtlFormat of type fullCtl cannot have delete commands"(){
        when:
        new CtlFormat(ver,nextUpdate,true,12,[addCommand,delCommand] as CtlCommand[])
        then:
        def e = thrown(IllegalArgumentException)
        e.message == "Illegal CtlFormat, fullCtl cannot have delete ctl commands."
    }

    def "Verify toString()"() {
        expect:
        new CtlFormat(ver, nextUpdate, false, 12, ctlCommands).toString() == """CtlFormat [
  version=1
  nextUpdate=Time32 [timeStamp=Mon Mar 18 14:14:14 CET 2019 (479999657)]
  isFullCtl=false
  ctlSequence=12
  ctlCommands=
    [add=[rca=[
        selfsignedRootCa=[
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
        ]
        linkRootCaCertificate=NONE
      ]
    ]]
    [delete=[cert=[1122334455667788]]]
]"""
        new CtlFormat(ver, nextUpdate, true, 12, [addCommand] as CtlCommand[]).toString() == """CtlFormat [
  version=1
  nextUpdate=Time32 [timeStamp=Mon Mar 18 14:14:14 CET 2019 (479999657)]
  isFullCtl=true
  ctlSequence=12
  ctlCommands=
    [add=[rca=[
        selfsignedRootCa=[
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
        ]
        linkRootCaCertificate=NONE
      ]
    ]]
]"""
        new CtlFormat(ver, nextUpdate, false, 12, [delCommand] as CtlCommand[]).toString() == """CtlFormat [
  version=1
  nextUpdate=Time32 [timeStamp=Mon Mar 18 14:14:14 CET 2019 (479999657)]
  isFullCtl=false
  ctlSequence=12
  ctlCommands=
    [delete=[cert=[1122334455667788]]]
]"""
        new CtlFormat(ver, nextUpdate, true, 12, [] as CtlCommand[]).toString() == """CtlFormat [
  version=1
  nextUpdate=Time32 [timeStamp=Mon Mar 18 14:14:14 CET 2019 (479999657)]
  isFullCtl=true
  ctlSequence=12
  ctlCommands=NONE
]"""
    }
}
