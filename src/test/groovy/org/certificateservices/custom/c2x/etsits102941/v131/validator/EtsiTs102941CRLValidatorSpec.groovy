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

import org.bouncycastle.util.encoders.Hex
import org.certificateservices.custom.c2x.common.crypto.CryptoManager
import org.certificateservices.custom.c2x.common.validator.CertificateRevokedException
import org.certificateservices.custom.c2x.common.validator.InvalidCRLException
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist.EtsiTs102941CRL
import org.certificateservices.custom.c2x.etsits102941.v131.generator.ETSITS102941MessagesCaGenerator
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

import static org.certificateservices.custom.c2x.etsits102941.v131.util.Etsi102941CRLHelperSpec.genCRL
import static org.certificateservices.custom.c2x.etsits102941.v131.util.TestPKI1.simpleDateFormat

/**
 * Unit tests for EtsiTs102941CRLValidator
 *
 * @author Philip Vendil
 */
class EtsiTs102941CRLValidatorSpec extends Specification {


    @Shared TestPKI1 testPKI1

    EtsiTs102941CRLValidator etsiTs102941CRLValidator
    Map<HashedId8, Certificate> trustStore
    CryptoManager cryptoManager
    SecuredDataGenerator securedDataGenerator

    def validDate = simpleDateFormat.parse("2020-02-08 10:11:10")

    def setupSpec(){
        testPKI1 = new TestPKI1()
    }

    def setup(){
        cryptoManager = BasePermissionValidatorSpec.cryptoManager

        securedDataGenerator = new SecuredDataGenerator(SecuredDataGenerator.DEFAULT_VERSION,
                cryptoManager, HashAlgorithm.sha256, Signature.SignatureChoices.ecdsaNistP256Signature)

        ETSI103097CertificateValidator certificateValidator = new ETSI103097CertificateValidator(cryptoManager, securedDataGenerator)

        etsiTs102941CRLValidator = new EtsiTs102941CRLValidator(cryptoManager, securedDataGenerator, certificateValidator)

        trustStore = securedDataGenerator.buildCertStore([testPKI1.rootca1, testPKI1.rootca2, testPKI1.rootca3])
    }


    def "Verify that unrevoked certificate in valid CRL doesn't throw any exceptions"(){
        when:
        etsiTs102941CRLValidator.verifyAndValidate(testPKI1.rootCA1Crl, testPKI1.rca1_ea2, validDate, null, trustStore, true)
        then:
        true
    }

    def "Verify that revoked certificate throws CertificateRevokedException"(){
        when:
        etsiTs102941CRLValidator.verifyAndValidate(testPKI1.rootCA1Crl, testPKI1.rca1_ea1, validDate, null, trustStore, true)
        then:
        def e = thrown CertificateRevokedException
        String certId = new String(Hex.encode(testPKI1.rca1_ea1.asHashedId8(cryptoManager).data))
        e.message == "Certificate HashedId8 [${certId}] is included in CRL."
    }

    def "Verify that not yet valid CRL throws InvalidCRLException"(){
        setup:
        def notYetValid = simpleDateFormat.parse("2020-02-07 10:11:30")
        when:
        etsiTs102941CRLValidator.verifyAndValidate(testPKI1.rootCA1Crl, testPKI1.rca1_ea2, notYetValid, null, trustStore, true)
        then:
        def e = thrown InvalidCRLException
        e.message == "Invalid CRL, not yet valid."
    }

    def "Verify that expired CRL throws InvalidCRLException"(){
        setup:
        def expired = simpleDateFormat.parse("2020-03-09 10:11:30")
        when:
        etsiTs102941CRLValidator.verifyAndValidate(testPKI1.rootCA1Crl, testPKI1.rca1_ea2, expired, null, trustStore, true)
        then:
        def e = thrown InvalidCRLException
        e.message == "CRL is expired."
    }

    def "Verify that CRL is verified to trust store and throws InvalidCRLException if not trusted."(){
        setup:
        def invalidTrustStore = securedDataGenerator.buildCertStore([testPKI1.rootca2])
        when:
        etsiTs102941CRLValidator.verifyAndValidate(testPKI1.rootCA1Crl, testPKI1.rca1_ea2, validDate, null, invalidTrustStore, true)
        then:
        def e = thrown InvalidCRLException
        e.message =~ "RootCA not trusted"
    }

    def "Verify that CRL signing certificate is validated and InvalidCRLException is thrown"(){
        setup:
        def checkDate = simpleDateFormat.parse("2010-03-01 10:11:10")
        EtsiTs102941CRL crl =  genCRL([thisUpdate : "2010-02-07 10:12:10",
                                                               nextUpdate : "2010-03-07 10:11:10",
                                                               entries    : [testPKI1.rca1_ea1],
                                                               signerChain: [testPKI1.rootca1],
                                                               signerKey  : testPKI1.rootCA1SigningKeys
        ]

        )
        when:
        etsiTs102941CRLValidator.verifyAndValidate(crl, testPKI1.rca1_ea2, checkDate, null, trustStore, true)
        then:
        def e = thrown InvalidCRLException
        e.message == "Error validating certificate chain of CRL: Invalid certificate in chain, not yet valid."
    }

    def "Verify that CRL signing certificate is checked for signing permissions"(){
        when:
        etsiTs102941CRLValidator.verifyAndValidate(testPKI1.rootCA3Crl, testPKI1.rca3_ea1, validDate, null, trustStore, true)
        then:
        def e = thrown InvalidCRLException
        e.message == "Error validating certificate chain of CRL: Couldn't find permission for CRLService (622): 01 in certificate."
    }

    def "Verify that invalid signed CRL is not accepted"(){
        setup:
        EtsiTs102941CRL crl = genCRL([thisUpdate : "2020-02-07 10:12:10",
                                      nextUpdate : "2020-03-07 10:11:10",
                                      entries    : [testPKI1.rca1_ea1, testPKI1.rca1_aa1],
                                      signerChain: [testPKI1.rootca1],
                                      signerKey  : testPKI1.rootCA2SigningKeys
        ])
        when:
        etsiTs102941CRLValidator.verifyAndValidate(crl, testPKI1.rca3_ea1, validDate, null, trustStore, true)
        then:
        def e = thrown InvalidCRLException
        e.message == "Couldn't verify the CRL."
    }


    def "Verify that CRL is self signed and accept all country code."(){
        GeographicRegion region = GeographicRegion.generateRegionForCountrys([1, 2, 3, 4, 5, 6, 7, 8, 9])
        when:
        etsiTs102941CRLValidator.verifyAndValidate(testPKI1.rootCA1Crl, testPKI1.rca1_ea2, validDate, region, trustStore, true)
        then:
        true
    }
}
