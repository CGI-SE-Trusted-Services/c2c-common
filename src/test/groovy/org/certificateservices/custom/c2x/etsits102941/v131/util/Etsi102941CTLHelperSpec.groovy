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
package org.certificateservices.custom.c2x.etsits102941.v131.util

import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.util.encoders.Hex
import org.certificateservices.custom.c2x.common.BaseStructSpec
import org.certificateservices.custom.c2x.common.crypto.CryptoManager
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.Version
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist.*
import org.certificateservices.custom.c2x.etsits102941.v131.generator.ETSITS102941MessagesCaGenerator
import org.certificateservices.custom.c2x.etsits102941.v131.generator.ETSITS102941SecureDataGenerator
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate
import org.certificateservices.custom.c2x.etsits103097.v131.generator.ETSISecuredDataGenerator
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.*
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.CertificateId
import org.certificateservices.custom.c2x.ieee1609dot2.validator.BasePermissionValidatorSpec
import spock.lang.Shared

import java.security.PrivateKey
import java.security.Security

import static org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist.CtlEntry.CtlEntryChoices.*
import static org.certificateservices.custom.c2x.etsits102941.v131.util.TestPKI1.simpleDateFormat

/**
 * Unit tests for Etsi102941CTLHelper
 *
 * @author Philip Vendil 2020-01-16
 */
class Etsi102941CTLHelperSpec extends BaseStructSpec {

    @Shared Etsi102941CTLHelper helper
    CertificateId id1 = new CertificateId(new Hostname("Test RootCA1 EA1"))
    CertificateId id2 = new CertificateId(new Hostname("Test RootCA1 EA2"))

    @Shared TestPKI1 testPKI1
    static ETSITS102941MessagesCaGenerator etsits102941MessagesCaGenerator

    @Shared CryptoManager cryptoManager
    static{
        Security.addProvider(new BouncyCastleProvider())
        ETSITS102941SecureDataGenerator etsiSecuredDataGenerator =  new ETSITS102941SecureDataGenerator(ETSISecuredDataGenerator.DEFAULT_VERSION, BasePermissionValidatorSpec.cryptoManager, HashAlgorithm.sha256, Signature.SignatureChoices.ecdsaNistP256Signature);
        etsits102941MessagesCaGenerator = new ETSITS102941MessagesCaGenerator(etsiSecuredDataGenerator)
    }

    def setupSpec(){
        cryptoManager = BasePermissionValidatorSpec.cryptoManager
        testPKI1 = new TestPKI1()
        helper = new Etsi102941CTLHelper(cryptoManager)
    }

    def "Verify that a  matching certificate is found for type ea"(){
        when:
        def l = helper.findCACtlEntries(testPKI1.fullRootCA1Ctl, ea, id1)
        then:
        l.size() == 1
        l[0].getEaEntry() != null
    }

    def "Verify that a list of one matching certificate is found for type ea with other id"(){
        when:
        def l = helper.findCACtlEntries(testPKI1.fullRootCA1Ctl, CtlEntry.CtlEntryChoices.ea, id2)
        then:
        l.size() == 1
        l[0].getEaEntry() != null
    }

    def "Verify that a list of one matching certificate is found for type aa"(){
        when:
        def l = helper.findCACtlEntries(testPKI1.fullRootCA1Ctl, CtlEntry.CtlEntryChoices.aa, new CertificateId(new Hostname("Test RootCA1 AA1")))
        then:
        l.size() == 1
        l[0].getAaEntry() != null
    }

    def "Verify that an empty list is returned if no ids is matching"(){
        when:
        def l = helper.findCACtlEntries(testPKI1.fullRootCA1Ctl, CtlEntry.CtlEntryChoices.aa, new CertificateId(new Hostname("noexists")))
        then:
        l.size() == 0
    }

    def "Verify that an empty list is returned if no type is matching"(){
        when:
        def l = helper.findCACtlEntries(testPKI1.fullRootCA1Ctl, CtlEntry.CtlEntryChoices.tlm, id1)
        then:
        l.size() == 0
    }

    def "Verify that findCACtlEntries with a delta CRL also adds new certificates to the list."(){
        when:
        def l = helper.findCACtlEntries(testPKI1.fullRootCA1Ctl, testPKI1.deltaRootCA1Ctl, CtlEntry.CtlEntryChoices.aa, new CertificateId(new Hostname("Test RootCA1 AA2")))
        then:
        l.size() == 1
        l[0].getAaEntry() != null
    }


    def "Verify that findCACtlEntries with a delta CRL does not return removed certificates."(){
        expect:
        helper.findCACtlEntries(testPKI1.fullRootCA1Ctl, null, CtlEntry.CtlEntryChoices.ea, new CertificateId(new Hostname("Test RootCA1 EA2"))).size() == 1
        helper.findCACtlEntries(testPKI1.fullRootCA1Ctl, testPKI1.deltaRootCA1Ctl, CtlEntry.CtlEntryChoices.ea, new CertificateId(new Hostname("Test RootCA1 EA2"))).size() == 0

    }

    def "Verify that an tlm entries can be found."(){
        setup:
        def tlmCtl = genCTL([ type: "tlmctl",
                              nextUpdate: "2020-02-07 10:10:10",
                              sequence: 1,
                              commands:[[
                                                command: "add",
                                                type: "tlm",
                                                selfsignedcert: testPKI1.tlm,
                                                accesspoint: "http://somecpoc"

                                        ],[
                                                command: "add",
                                                type: "rca",
                                                selfsignedcert: testPKI1.rootca2
                                        ]],
                              signerChain: [testPKI1.tlm],
                              signerKey: testPKI1.tlmSigningKeys
        ])
        when:
        def l = helper.findCACtlEntries(tlmCtl, tlm, new CertificateId(new Hostname("Some TLM")))
        then:
        l.size() == 1
        l[0].getTlmEntry() != null
    }

    def "Verify that an rca entries can be found."(){
        when:
        def l = helper.findCACtlEntries(testPKI1.fullTlmCtl, rca, new CertificateId(new Hostname("Test RootCA1")))
        then:
        l.size() == 1
        l[0].getRcaEntry() != null
    }

    def "Verify that findCACtlEntries return certificates entries for all types."(){
        when:
        def r1 = helper.getCACtlEntries(testPKI1.fullRootCA1Ctl, null,  [ea,aa] as CtlEntry.CtlEntryChoices[])
        then:
        r1.size() == 3
        when:
        println testPKI1.deltaRootCA1Ctl
        def r2 = helper.getCACtlEntries(testPKI1.fullRootCA1Ctl, testPKI1.deltaRootCA1Ctl,  [ea,aa] as CtlEntry.CtlEntryChoices[])
        then:
        r2.size() == 3
        r2[1].getEaEntry() == null
    }

    def "Verify that getDCCtlEntries return ctl entries for dc types."(){
        when:
        def r1 = helper.getDCCtlEntries(testPKI1.fullRootCA1Ctl,null)
        then:
        r1.size() == 1
        r1[0].getDcEntry().url.url == "http://somedc"
        when:
        def r2 = helper.getDCCtlEntries(testPKI1.fullRootCA1Ctl,testPKI1.deltaRootCA1Ctl)
        then:
        r2.size() == 1
        r2[0].getDcEntry().url.url == "http://somedc2"
        when:
        def r3 = helper.getDCCtlEntries(testPKI1.fullRootCA2Ctl,null)
        then:
        r3.size() == 0

    }

    def "Verify that getDCCtlEntries return ctl entries for dc types filtered by a specific certId."(){
        expect:
        helper.getDCCtlEntries(testPKI1.fullRootCA1Ctl,null, testPKI1.rootca1.asHashedId8(cryptoManager)).size() == 1
        helper.getDCCtlEntries(testPKI1.fullRootCA1Ctl,testPKI1.deltaRootCA1Ctl, testPKI1.rootca2.asHashedId8(cryptoManager)).size()  == 1
        helper.getDCCtlEntries(testPKI1.fullRootCA1Ctl,testPKI1.deltaRootCA1Ctl, testPKI1.rootca3.asHashedId8(cryptoManager)).size()  == 0
    }




    static EtsiTs102941CTL genCTL(Map m){
        Time32 nextUpdate = new Time32(simpleDateFormat.parse(m.nextUpdate))
        boolean isFullCTL = m.delta != null ? !m.delta : true
        int sequence = m.sequence != null ? m.sequence : 1
        CtlCommand[] ctlCommands = parseCTLCommands(m.commands)

        if(m.type == "rcactl") {
            ToBeSignedRcaCtl toBeSignedRcaCtl = new ToBeSignedRcaCtl(Version.V1, nextUpdate, isFullCTL, sequence, ctlCommands)
            return etsits102941MessagesCaGenerator.genRcaCertificateTrustListMessage(new Time64(new Date()), toBeSignedRcaCtl,
                    (EtsiTs103097Certificate[]) m.signerChain, (PrivateKey) m.signerKey.private)
        }else {
            ToBeSignedTlmCtl toBeSignedTlmCtl = new ToBeSignedTlmCtl(Version.V1, nextUpdate, isFullCTL, sequence, ctlCommands)
            return etsits102941MessagesCaGenerator.genTlmCertificateTrustListMessage(new Time64(new Date()), toBeSignedTlmCtl,
                    (EtsiTs103097Certificate[]) m.signerChain, (PrivateKey)  m.signerKey.private)
        }
    }

    static CtlCommand[] parseCTLCommands(List commands){
        List retval = []
        for(Map m : commands){
            if(m.command == "add"){
                CtlEntry ctlEntry
                switch(m.type){
                    case "tlm":
                        ctlEntry = new CtlEntry(new TlmEntry(m.selfsignedcert, m.linkcert,new Url(m.accesspoint)))
                        break
                    case "rca":
                        ctlEntry = new CtlEntry(new RootCaEntry(m.selfsignedcert, m.linkcert))
                        break
                    case "ea":
                        ctlEntry = new CtlEntry(new EaEntry(m.eacert, new Url(m.aaaccesspoint), new Url(m.itsaccesspoint)))
                        break
                    case "aa":
                        ctlEntry = new CtlEntry(new AaEntry(m.aacert, new Url(m.accesspoint)))
                        break
                    case "dc":
                        SequenceOfHashedId8 certIds = new SequenceOfHashedId8(m.certIds)
                        ctlEntry = new CtlEntry(new DcEntry(new Url(m.url), certIds))
                        break
                }
                retval << new CtlCommand(ctlEntry)
            }
            if(m.command == "del"){
                CtlDelete ctlDelete
                if(m.type == "dc"){
                    ctlDelete = new CtlDelete(new DcDelete(m.url))
                }else{
                    ctlDelete = new CtlDelete(m.certId)
                }
                retval << new CtlCommand(ctlDelete)
            }
        }

        return retval as CtlCommand[]
    }

}
