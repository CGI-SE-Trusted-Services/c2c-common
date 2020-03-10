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
package org.certificateservices.custom.c2x.etsits102941.v131.validator

import org.certificateservices.custom.c2x.common.crypto.CryptoManager
import org.certificateservices.custom.c2x.common.validator.InvalidCRLException
import org.certificateservices.custom.c2x.common.validator.InvalidCTLException
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist.CtlEntry
import org.certificateservices.custom.c2x.etsits102941.v131.util.TestPKI1
import org.certificateservices.custom.c2x.etsits103097.v131.validator.ETSI103097CertificateValidator
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.GeographicRegion
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashAlgorithm
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId8
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate
import org.certificateservices.custom.c2x.ieee1609dot2.generator.SecuredDataGenerator
import org.certificateservices.custom.c2x.ieee1609dot2.validator.BasePermissionValidatorSpec
import spock.lang.Shared
import spock.lang.Specification

import static org.certificateservices.custom.c2x.etsits102941.v131.util.Etsi102941CTLHelperSpec.genCTL
import static org.certificateservices.custom.c2x.etsits102941.v131.util.TestPKI1.simpleDateFormat


/**
 * Unit tests for EtsiTs102941CTLValidator
 *
 * @author Philip Vendil
 */
class EtsiTs102941CTLValidatorSpec extends Specification {

    @Shared TestPKI1 testPKI1

    EtsiTs102941CTLValidator etsiTs102941CTLValidator
    Map<HashedId8, Certificate> trustStore
    CryptoManager cryptoManager
    SecuredDataGenerator securedDataGenerator

    def validDate = simpleDateFormat.parse("2020-02-06 10:11:10")

    def eaAndAATypes
    def eaStoreTypes

    def setupSpec(){
        testPKI1 = new TestPKI1()
    }

    def setup(){
        cryptoManager = BasePermissionValidatorSpec.cryptoManager

        securedDataGenerator = new SecuredDataGenerator(SecuredDataGenerator.DEFAULT_VERSION,
                cryptoManager, HashAlgorithm.sha256, Signature.SignatureChoices.ecdsaNistP256Signature)

        ETSI103097CertificateValidator certificateValidator = new ETSI103097CertificateValidator(cryptoManager, securedDataGenerator)

        etsiTs102941CTLValidator = new EtsiTs102941CTLValidator(cryptoManager, securedDataGenerator, certificateValidator)

        trustStore = securedDataGenerator.buildCertStore([testPKI1.rootca1, testPKI1.rootca2, testPKI1.rootca3])

        eaAndAATypes = [CtlEntry.CtlEntryChoices.ea,CtlEntry.CtlEntryChoices.aa] as CtlEntry.CtlEntryChoices[]
        eaStoreTypes = [CtlEntry.CtlEntryChoices.ea] as CtlEntry.CtlEntryChoices[]

    }

    def "Verify that valid CTLs with full CTL returns  generated certStore"(){
        when:
        def result = etsiTs102941CTLValidator.verifyAndValidate(testPKI1.fullRootCA1Ctl, null, validDate, null, trustStore, true, eaAndAATypes)
        then:
        result.size() == 3
        result[testPKI1.rca1_ea1.asHashedId8(cryptoManager)] == testPKI1.rca1_ea1
        result[testPKI1.rca1_aa1.asHashedId8(cryptoManager)] == testPKI1.rca1_aa1
        result[testPKI1.rca1_ea2.asHashedId8(cryptoManager)] == testPKI1.rca1_ea2
        when:
        result = etsiTs102941CTLValidator.verifyAndValidate(testPKI1.fullRootCA1Ctl, null, validDate, null, trustStore, true, eaStoreTypes)
        then:
        result.size() == 2
        result[testPKI1.rca1_ea1.asHashedId8(cryptoManager)] == testPKI1.rca1_ea1
        result[testPKI1.rca1_ea2.asHashedId8(cryptoManager)] == testPKI1.rca1_ea2
    }

    def "Verify that valid CTLs with full CTL and delta returns only valid certificates in generated certStore"(){
        when:
        def result = etsiTs102941CTLValidator.verifyAndValidate(testPKI1.fullRootCA1Ctl, testPKI1.deltaRootCA1Ctl, validDate, null, trustStore, true, eaAndAATypes)
        then:
        result.size() == 3
        result[testPKI1.rca1_aa2.asHashedId8(cryptoManager)] == testPKI1.rca1_aa2
        result[testPKI1.rca1_ea2.asHashedId8(cryptoManager)] == null
    }

    def "Verify that type of CRL is checked against what is expected"(){
        when:
        etsiTs102941CTLValidator.verifyAndValidate(testPKI1.deltaRootCA1Ctl, validDate, null, null,  trustStore, true, eaAndAATypes, true, true)
        then:
        def e = thrown(InvalidCTLException)
        e.message == "Invalid CTL type, expected full but CTL was of type: delta"
        when:
        etsiTs102941CTLValidator.verifyAndValidate(testPKI1.fullRootCA1Ctl, validDate,null, null,  trustStore, true, eaAndAATypes, false, true)
        then:
        e = thrown(InvalidCTLException)
        e.message == "Invalid CTL type, expected delta but CTL was of type: full"
    }

    def "Verify that InvalidCTLException is thrown for full CTL with invalid signature"(){
        setup:
        def fullCtl = genCTL([ type: "rcactl",
                                  nextUpdate: "2020-02-07 10:10:10",
                                  sequence: 1,
                                  commands:[[
                                                    command: "add",
                                                    type: "ea",
                                                    eacert: testPKI1.rca1_ea1,
                                                    aaaccesspoint: "http://someaaaccesspoint",
                                                    itsaccesspoint: "http://someitsaccesspoint"

                                            ]],
                                  signerChain: [testPKI1.rootca1],
                                  signerKey: testPKI1.rootCA2SigningKeys
        ])
        when:
        etsiTs102941CTLValidator.verifyAndValidate(fullCtl, null, validDate,null,  trustStore, true, eaAndAATypes)
        then:
        def e = thrown(InvalidCTLException)
        e.message == "Couldn't verify the full CTL."
    }

    def "Verify that InvalidCTLException is thrown for delta CTL with invalid signature"(){
        setup:
        def deltaCtl = genCTL([ type: "rcactl",
                               nextUpdate: "2020-02-07 10:10:10",
                               sequence: 1,
                               delta: true,
                               commands:[[
                                                 command: "add",
                                                 type: "ea",
                                                 eacert: testPKI1.rca1_ea2,
                                                 aaaccesspoint: "http://someaaaccesspoint",
                                                 itsaccesspoint: "http://someitsaccesspoint"

                                         ]],
                               signerChain: [testPKI1.rootca1],
                               signerKey: testPKI1.rootCA2SigningKeys
        ])
        when:
        etsiTs102941CTLValidator.verifyAndValidate(testPKI1.fullRootCA1Ctl, deltaCtl, validDate, null, trustStore, true, eaAndAATypes)
        then:
        def e = thrown(InvalidCTLException)
        e.message == "Couldn't verify the delta CTL."
    }


    def "Verify that InvalidCTLException is thrown for CTL with untrusted signature"(){
        setup:
        def invalidTrustStore = securedDataGenerator.buildCertStore([ testPKI1.rootca2, testPKI1.rootca3])
        when:
        etsiTs102941CTLValidator.verifyAndValidate(testPKI1.fullRootCA1Ctl, null, validDate, null, invalidTrustStore, true, eaAndAATypes)
        then:
        def e = thrown(InvalidCTLException)
        e.message =~ "CTL Issuer not trusted:"
    }

    def "Verify that InvalidCTLException is thrown if sequence number miss match between full and delta CTL."(){
        setup:
        def deltaCtl = genCTL([ type: "rcactl",
                                nextUpdate: "2020-02-07 10:10:10",
                                sequence: 2,
                                delta: true,
                                commands:[[
                                                  command: "add",
                                                  type: "ea",
                                                  eacert: testPKI1.rca1_ea2,
                                                  aaaccesspoint: "http://someaaaccesspoint",
                                                  itsaccesspoint: "http://someitsaccesspoint"

                                          ]],
                                signerChain: [testPKI1.rootca1],
                                signerKey: testPKI1.rootCA1SigningKeys
        ])
        when:
        etsiTs102941CTLValidator.verifyAndValidate(testPKI1.fullRootCA1Ctl, deltaCtl, validDate, null, trustStore, true, eaAndAATypes)
        then:
        def e = thrown(InvalidCTLException)
        e.message == "Error deltaCTL sequence doesn't match sequence in full CTL."
    }

    def "Verify that InvalidCTLException is thrown if signer of delta CTL doesn't match rootCA CTL."(){
        setup:
        def deltaCtl = genCTL([ type: "rcactl",
                                nextUpdate: "2020-02-07 10:10:10",
                                sequence: 1,
                                delta: true,
                                commands:[[
                                                  command: "add",
                                                  type: "ea",
                                                  eacert: testPKI1.rca2_ea1,
                                                  aaaccesspoint: "http://someaaaccesspoint",
                                                  itsaccesspoint: "http://someitsaccesspoint"

                                          ]],
                                signerChain: [testPKI1.rootca2],
                                signerKey: testPKI1.rootCA2SigningKeys
        ])
        when:
        etsiTs102941CTLValidator.verifyAndValidate(testPKI1.fullRootCA1Ctl, deltaCtl, validDate, null, trustStore, true, eaAndAATypes)
        then:
        def e = thrown(InvalidCTLException)
        e.message == "Full CTL and delta CTL signerIdentifiers doesn't match."
    }

    def "Verify that InvalidCTLException is thrown if fullCTL have expired"(){
        setup:
        def expiredDate = simpleDateFormat.parse("2020-02-10 10:11:10")
        when:
        etsiTs102941CTLValidator.verifyAndValidate(testPKI1.fullRootCA1Ctl, null, expiredDate, null, trustStore, true, eaAndAATypes)
        then:
        def e = thrown(InvalidCTLException)
        e.message == "full CTL is expired."
    }

    def "Verify that InvalidCTLException is thrown if deltaCTL have expired"(){
        def expiredDate = simpleDateFormat.parse("2020-02-09 10:11:10")
        when:
        etsiTs102941CTLValidator.verifyAndValidate(testPKI1.fullRootCA1Ctl, testPKI1.deltaRootCA1Ctl, expiredDate, null, trustStore, true, eaAndAATypes)
        then:
        def e = thrown(InvalidCTLException)
        e.message == "delta CTL is expired."
    }

    def "Verify that InvalidCTLException is thrown if signing certificate is invalid."(){
        setup:
        def checkDate = simpleDateFormat.parse("2010-03-01 10:11:10")
        when:
        etsiTs102941CTLValidator.verifyAndValidate(testPKI1.fullRootCA1Ctl, null, checkDate, null, trustStore, true, eaAndAATypes)
        then:
        def e = thrown(InvalidCTLException)
        e.message =~ "Error validating certificate chain of full CTL"
    }

    def "Verify that InvalidCTLException is thrown if signing certificate doesn't have permissions."(){
        when:
        etsiTs102941CTLValidator.verifyAndValidate(testPKI1.fullRootCA3Ctl, null, validDate, null, trustStore, true, eaAndAATypes)
        then:
        def e = thrown(InvalidCTLException)
        e.message == "Error validating certificate chain of full CTL: Couldn't find permission for CTLService (624): 0130 in certificate."
    }


    def "Verify that CTL is self signed and accept all country code."(){
        GeographicRegion region = GeographicRegion.generateRegionForCountrys([1, 2, 3, 4,5 , 6, 7, 8, 9])
        when:
        def result = etsiTs102941CTLValidator.verifyAndValidate(testPKI1.fullRootCA1Ctl, testPKI1.deltaRootCA1Ctl, validDate, region, trustStore, true, eaAndAATypes)
        then:
        result.size() == 3
        result[testPKI1.rca1_aa2.asHashedId8(cryptoManager)] == testPKI1.rca1_aa2
        result[testPKI1.rca1_ea2.asHashedId8(cryptoManager)] == null
    }


    def "Verify that CTL contains not valid country code."(){
        GeographicRegion region = GeographicRegion.generateRegionForCountrys([100])
        Map<HashedId8, Certificate> trustStoreRegion = securedDataGenerator.buildCertStore([testPKI1.rootca4]) // 752=sweden in the store
        when:
        def result = etsiTs102941CTLValidator.verifyAndValidate(testPKI1.fullRootCA4Ctl, testPKI1.deltaRootCA4Ctl, validDate, region, trustStoreRegion, true, eaAndAATypes)
        then:
        def e = thrown(InvalidCTLException)
        e.message == "Error validating certificate chain of full CTL: Invalid set of countryOnly ids in certificate."
    }
}
