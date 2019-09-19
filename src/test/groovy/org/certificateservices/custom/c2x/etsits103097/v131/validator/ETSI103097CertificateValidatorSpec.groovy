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

import org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.EndEntityType
import org.certificateservices.custom.c2x.ieee1609dot2.validator.CountryOnlyRegionValidator
import org.certificateservices.custom.c2x.ieee1609dot2.validator.Ieee1609Dot2TimeValidator
import spock.lang.Specification

import static org.certificateservices.custom.c2x.etsits103097.v131.validator.SecuredCertificateRequestServicePermissions.SIGN_AUTH_REQ
import static org.certificateservices.custom.c2x.etsits103097.v131.validator.SecuredCertificateRequestServicePermissions.SIGN_AUTH_VALIDATION_RESP
import static org.certificateservices.custom.c2x.etsits103097.v131.validator.SecuredCertificateRequestServicePermissions.VERSION_1

/**
 * Unit tests for ETSI103097CertificateValidator
 *
 * @author Philip Vendil, p.vendil@cgi.com
 */
class ETSI103097CertificateValidatorSpec extends Specification {

    Ieee1609Dot2CryptoManager cryptoManager = Mock(Ieee1609Dot2CryptoManager)

    def "Verify that default constructor populates fields correctly."(){
        when:
        ETSI103097CertificateValidator validator = new ETSI103097CertificateValidator(cryptoManager)
        then:
        validator.cryptoManager == cryptoManager
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
        ETSI103097CertificateValidator validator = new ETSI103097CertificateValidator(cryptoManager, timeValidator, regionValidator, permissionValidator)
        then:
        validator.cryptoManager == cryptoManager
        validator.timeValidator == timeValidator
        validator.regionValidator == regionValidator
        validator.permissionValidator == permissionValidator
    }

    def "Verify that checkCertServicePermissionInAppPermissions calls corresponding permissionValidator method"(){
        setup:
        def timeValidator = new Ieee1609Dot2TimeValidator()
        def regionValidator = new CountryOnlyRegionValidator()
        def permissionValidator = Mock(ETSI103097PermissionValidator)
        ETSI103097CertificateValidator validator = new ETSI103097CertificateValidator(cryptoManager, timeValidator, regionValidator, permissionValidator)
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
        ETSI103097CertificateValidator validator = new ETSI103097CertificateValidator(cryptoManager, timeValidator, regionValidator, permissionValidator)
        Certificate[] chain = [] as Certificate[]
        when:
        validator.checkCertServicePermissionInIssuePermissions(VERSION_1, SIGN_AUTH_VALIDATION_RESP, eEType, 1, chain)
        then:
        1 * permissionValidator.checkCertServicePermissionInIssuePermissions(VERSION_1, SIGN_AUTH_VALIDATION_RESP, eEType, 1, chain)
    }
}
