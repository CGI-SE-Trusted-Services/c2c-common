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
package org.certificateservices.custom.c2x.etsits103097.v131.validator;

import org.certificateservices.custom.c2x.common.Certificate;
import org.certificateservices.custom.c2x.common.validator.InvalidCertificateException;
import org.certificateservices.custom.c2x.common.validator.RegionValidator;
import org.certificateservices.custom.c2x.common.validator.TimeValidator;
import org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.EndEntityType;
import org.certificateservices.custom.c2x.ieee1609dot2.validator.BaseCertificateValidator;
import org.certificateservices.custom.c2x.ieee1609dot2.validator.CountryOnlyRegionValidator;
import org.certificateservices.custom.c2x.ieee1609dot2.validator.Ieee1609Dot2TimeValidator;

/**
 * Certificate Validator for verifying and validating ETSI103097Certificates.
 * <p>
 *     The validator verifies the signature, region, validity and that permissions are consistent.
 * </p>
 * <p>
 *     For regions is only countryOnly regions allowed. No other.
 * </p>
 * @author Philip Vendil, p.vendil@cgi.com
 */
public class ETSI103097CertificateValidator extends BaseCertificateValidator {

    /**
     * Default certificate validator constructor.
     * @param cryptoManager the crypto manager to use for cryptographic operations.
     */
    public ETSI103097CertificateValidator(Ieee1609Dot2CryptoManager cryptoManager) {
        super(cryptoManager, new Ieee1609Dot2TimeValidator(), new CountryOnlyRegionValidator(), new ETSI103097PermissionValidator());
    }

    /**
     * Flexible constructor where it is possible to override the validation checks.
     * @param cryptoManager the crypto manager to use for cryptographic operations.
     * @param timeValidator a TimeValidator implementation
     * @param regionValidator a RegionValidation implementation
     * @param permissionValidator a ETSI103097PermissionValidator permission validator.
     */
    public ETSI103097CertificateValidator(Ieee1609Dot2CryptoManager cryptoManager, TimeValidator timeValidator, RegionValidator regionValidator, ETSI103097PermissionValidator permissionValidator) {
        super(cryptoManager, timeValidator, regionValidator, permissionValidator);
    }



    /**
     * Method to check if the first certificate in supplied chain have a specific appPermission set in
     * its SecuredCertificateRequestService (623) SSP Data.
     *
     * @param ssPVersion the version byte of the SSP Data (Use SecuredCertificateRequestServicePermissions.VERSION_ constants)
     * @param ssPPermissions the permission to look up in the SSP Data (Use SecuredCertificateRequestServicePermission constants)
     * @param certificateChain the certificate chain to check permission, only the first certificate that have its certificate checked.
     * @throws InvalidCertificateException if given permission wasn't found in the certificate.
     */
    public void checkCertServicePermissionInAppPermissions(byte ssPVersion, byte ssPPermissions, Certificate[] certificateChain) throws InvalidCertificateException{
        ((ETSI103097PermissionValidator) permissionValidator).checkCertServicePermissionInAppPermissions(ssPVersion,ssPPermissions,certificateChain);
    }

    /**
     * Method to check if the first certificate in supplied chain have a specific certIssuePermission set in
     * its SecuredCertificateRequestService (623) SSP Data.
     *
     * @param ssPVersion the version byte of the SSP Data (Use SecuredCertificateRequestServicePermissions.VERSION_ constants)
     * @param ssPPermissions the permission to look up in the SSP Data (Use SecuredCertificateRequestServicePermission constants)
     * @param endEntityType the end entity type to lookup
     * @param chainLengthIndex index parameter send to retrieve the correct group permissions from certificate. If validating chain that starts with end
     *                         entity certificate should chainLengthIndex be 0, if certificate chain starts with issuer of end entity certificate it should
     *                         be 1 and so on incremented up to root certificate in chain.
     * @param certificateChain the certificate chain to lookup cert issuer permissions if the first certificate.
     * @throws InvalidCertificateException if no given permissions was found in certificate.
     */
    public void checkCertServicePermissionInIssuePermissions(byte ssPVersion, byte ssPPermissions, EndEntityType endEntityType, int chainLengthIndex, Certificate[] certificateChain) throws InvalidCertificateException{
        ((ETSI103097PermissionValidator) permissionValidator).checkCertServicePermissionInIssuePermissions(ssPVersion,ssPPermissions,endEntityType,chainLengthIndex,certificateChain);
    }

}
