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
package org.certificateservices.custom.c2x.etsits103097.v131.validator

import org.certificateservices.custom.c2x.common.BadArgumentException
import org.certificateservices.custom.c2x.common.validator.CertificateRevokedException
import org.certificateservices.custom.c2x.common.validator.InvalidCTLException
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist.CtlEntry
import org.certificateservices.custom.c2x.etsits102941.v131.generator.ETSITS102941SecureDataGenerator
import org.certificateservices.custom.c2x.etsits102941.v131.util.TestPKI1
import org.certificateservices.custom.c2x.etsits103097.v131.generator.ETSISecuredDataGenerator
import org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashAlgorithm
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.EndEntityType
import org.certificateservices.custom.c2x.ieee1609dot2.generator.SecuredDataGenerator
import org.certificateservices.custom.c2x.ieee1609dot2.validator.BasePermissionValidatorSpec
import org.certificateservices.custom.c2x.ieee1609dot2.validator.CountryOnlyRegionValidator
import org.certificateservices.custom.c2x.ieee1609dot2.validator.Ieee1609Dot2TimeValidator
import spock.lang.Shared
import spock.lang.Specification

import static org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist.CtlEntry.CtlEntryChoices.dc
import static org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist.CtlEntry.CtlEntryChoices.ea
import static org.certificateservices.custom.c2x.etsits103097.v131.validator.SecuredCertificateRequestServicePermissions.SIGN_AUTH_VALIDATION_RESP
import static org.certificateservices.custom.c2x.etsits103097.v131.validator.SecuredCertificateRequestServicePermissions.VERSION_1

/**
 * Unit tests for ETSI103097CertificateValidator
 *
 * @author Philip Vendil, p.vendil@cgi.com
 */
class ETSI103097CertificateValidatorSpec extends Specification {

    Ieee1609Dot2CryptoManager cryptoManager
    SecuredDataGenerator securedDataGenerator
    ETSI103097CertificateValidator validator

    @Shared TestPKI1 testPKI1

    def setupSpec(){
        testPKI1 = new TestPKI1()
    }

    def setup(){
        cryptoManager = BasePermissionValidatorSpec.cryptoManager
        securedDataGenerator = new ETSITS102941SecureDataGenerator(ETSISecuredDataGenerator.DEFAULT_VERSION, BasePermissionValidatorSpec.cryptoManager, HashAlgorithm.sha256, Signature.SignatureChoices.ecdsaNistP256Signature);
        validator  = new ETSI103097CertificateValidator(cryptoManager, securedDataGenerator)
    }

    def "Verify that default constructor populates fields correctly."(){
        expect:
        validator.cryptoManager == cryptoManager
        validator.securedDataGenerator == securedDataGenerator
        validator.etsiTs102941CRLValidator != null
        validator.etsiTs102941CTLValidator != null
        validator.timeValidator instanceof Ieee1609Dot2TimeValidator
        validator.regionValidator instanceof CountryOnlyRegionValidator
        validator.permissionValidator instanceof ETSI103097PermissionValidator
    }

    def "Verify that flexible constructor populates fields correctly."(){
        setup:
        def timeValidator = new Ieee1609Dot2TimeValidator()
        def regionValidator = new CountryOnlyRegionValidator()
        def permissionValidator = new ETSI103097PermissionValidator()
        when:
        ETSI103097CertificateValidator validator = new ETSI103097CertificateValidator(cryptoManager, securedDataGenerator,timeValidator, regionValidator, permissionValidator)
        then:
        validator.cryptoManager == cryptoManager
        validator.securedDataGenerator == securedDataGenerator
        validator.etsiTs102941CRLValidator != null
        validator.etsiTs102941CTLValidator != null
        validator.timeValidator instanceof Ieee1609Dot2TimeValidator
        validator.regionValidator instanceof CountryOnlyRegionValidator
        validator.permissionValidator instanceof ETSI103097PermissionValidator
    }

    def "Verify that checkCertServicePermissionInAppPermissions calls corresponding permissionValidator method"(){
        setup:
        def timeValidator = new Ieee1609Dot2TimeValidator()
        def regionValidator = new CountryOnlyRegionValidator()
        def permissionValidator = Mock(ETSI103097PermissionValidator)
        ETSI103097CertificateValidator validator = new ETSI103097CertificateValidator(cryptoManager, securedDataGenerator, timeValidator, regionValidator, permissionValidator)
        Certificate[] chain = [] as Certificate[]
        when:

        validator.checkCertServicePermissionInAppPermissions(VERSION_1, SIGN_AUTH_VALIDATION_RESP, chain)
        then:
        1 * permissionValidator.checkCertServicePermissionInAppPermissions(VERSION_1, SIGN_AUTH_VALIDATION_RESP, chain)
    }

    def "Verify that checkCertServicePermissionInIssuePermissions calls corresponding permissionValidator method"(){
        setup:
        def timeValidator = new Ieee1609Dot2TimeValidator()
        def regionValidator = new CountryOnlyRegionValidator()
        def permissionValidator = Mock(ETSI103097PermissionValidator)
        def eEType = new EndEntityType(false,true)
        ETSI103097CertificateValidator validator = new ETSI103097CertificateValidator(cryptoManager, securedDataGenerator, timeValidator, regionValidator, permissionValidator)
        Certificate[] chain = [] as Certificate[]
        when:
        validator.checkCertServicePermissionInIssuePermissions(VERSION_1, SIGN_AUTH_VALIDATION_RESP, eEType, 1, chain)
        then:
        1 * permissionValidator.checkCertServicePermissionInIssuePermissions(VERSION_1, SIGN_AUTH_VALIDATION_RESP, eEType, 1, chain)
    }

    def "Verify that verifyAndValidate is successful with valid ECTL and RCACTL, with deltas and CRL."(){
        setup:
        def checkDate = TestPKI1.simpleDateFormat.parse("2020-02-07 10:13:10")
        when:
        validator.verifyAndValidate(testPKI1.rca1_ea1_ec1, checkDate, null, new EndEntityType(false,true),
                testPKI1.fullRootCA1Ctl, testPKI1.deltaRootCA1Ctl, testPKI1.emptyRootCA1Crl,testPKI1.fullTlmCtl,
                testPKI1.deltaTlmCtl, [testPKI1.tlm] as org.certificateservices.custom.c2x.common.Certificate[], [ea, dc] as CtlEntry.CtlEntryChoices[], true)

        then:
        true
    }

    def "Verify that verifyAndValidate is successful with valid ECTL and RCACTL, without deltas or CRL."(){
        setup:
        def checkDate = TestPKI1.simpleDateFormat.parse("2020-02-07 10:13:10")
        when:
        validator.verifyAndValidate(testPKI1.rca1_ea1_ec1, checkDate, null, new EndEntityType(false,true),
                testPKI1.fullRootCA1Ctl, null, null,testPKI1.fullTlmCtl,
                null, [testPKI1.tlm] as org.certificateservices.custom.c2x.common.Certificate[], [ea, dc] as CtlEntry.CtlEntryChoices[], true)

        then:
        true
    }

    def "Verify that verifyAndValidate verifies the ECTL."(){
        setup:
        def checkDate = TestPKI1.simpleDateFormat.parse("2020-02-07 10:13:10")
        when:
        validator.verifyAndValidate(testPKI1.rca1_ea1_ec1, checkDate, null, new EndEntityType(false,true),
                testPKI1.fullRootCA1Ctl, null, null,testPKI1.fullTlmCtl,
                testPKI1.deltaTlmCtl, [testPKI1.rootca2] as org.certificateservices.custom.c2x.common.Certificate[], [ea, dc] as CtlEntry.CtlEntryChoices[], true)

        then:
        def e = thrown(InvalidCTLException)
        e.message =~ "Invalid ECTL: CTL Issuer not trusted: Error last certificate in chain wasn't a trust anchor: HashedId8"
    }

    def "Verify that verifyAndValidate verifies the RCACTL."(){
        setup:
        def checkDate = TestPKI1.simpleDateFormat.parse("2020-02-07 10:13:10")
        when:
        // Test with a ec whose EA is removed in rca delta CTL.
        validator.verifyAndValidate(testPKI1.rca1_ea2_ec1, checkDate, null, new EndEntityType(false,true),
                testPKI1.fullRootCA1Ctl, testPKI1.deltaRootCA1Ctl, null,testPKI1.fullTlmCtl,
                testPKI1.deltaTlmCtl, [testPKI1.tlm] as org.certificateservices.custom.c2x.common.Certificate[], [ea, dc] as CtlEntry.CtlEntryChoices[], true)

        then:
        def e = thrown(BadArgumentException)
        e.message =~ "Error no certificate found in certstore for id :"
    }

    def "Verify that verifyAndValidate verifies the RCA CRL."(){
        setup:
        def checkDate = TestPKI1.simpleDateFormat.parse("2020-02-07 10:13:10")
        when:
        // Test with a ec whose EA is removed in rca delta CTL.
        validator.verifyAndValidate(testPKI1.rca1_ea1_ec1, checkDate, null, new EndEntityType(false,true),
                testPKI1.fullRootCA1Ctl, testPKI1.deltaRootCA1Ctl, testPKI1.rootCA1Crl,testPKI1.fullTlmCtl,
                testPKI1.deltaTlmCtl, [testPKI1.tlm] as org.certificateservices.custom.c2x.common.Certificate[], [ea, dc] as CtlEntry.CtlEntryChoices[], true)

        then:
        def e = thrown(CertificateRevokedException)
        e.message =~ "is included in CRL."
    }

}
