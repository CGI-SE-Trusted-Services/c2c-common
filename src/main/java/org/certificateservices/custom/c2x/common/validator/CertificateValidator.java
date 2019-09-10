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
package org.certificateservices.custom.c2x.common.validator;

import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.GeographicRegion;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId8;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.EndEntityType;

import java.security.NoSuchAlgorithmException;
import java.util.Date;
import java.util.Map;

/**
 * Interface to validate that a certificate is valid regarding to signature, validity, region and permissions.
 */
public interface CertificateValidator {

    /**
     * Method that verifies and validates all permissions on the build certificate chain.
     * <p>
     *     The method will build a chain for the certificate from the set of known certificates
     *     and the trust anchors.
     * </p>
     *
     *
     * For each certificate in the built chain it will check.
     * <ul>
     *     <li>Signature verifies</li>
     *     <li>Certificates validity</li>
     *     <li>Region matches</li>
     *     <li>App Permissions/Cert Issue Permissions</li>
     * </ul>
     * <p>
     *   <b>The method does not currently check revocation information.</b>
     * </p>
     * <p>
     *   <b>Permissions is only checked that it is consistent upwards in the chain. It does not check a specific permission</b>
     * </p>
     *
     * @param certificate the certificate to verify and validate
     * @param checkDate the date to check validity of certificate chain against.
     * @param checkRegion the region to check against, if null is region check skipped.
     * @param targetEndEntityType the type of end entity tree to check.
     * @param certStore a certstore that contains all intermediate CA certificates that is needed to build the chain.
     * @param trustStore a certstore of root ca certificates that are trusted.
     * @param entireChain if entireChain should be validated or only first certificate in chain.
     * @throws IllegalArgumentException if one of the parameters where invalid.
     * @throws InvalidCertificateException if one of the certificate in the build certificate chain was invalid.
     * @throws NoSuchAlgorithmException if use hash algorithm isn't supported by the system.
     */
    void verifyAndValidate(Certificate certificate, Date checkDate, GeographicRegion checkRegion,
                           EndEntityType targetEndEntityType, Map<HashedId8, Certificate> certStore,
                           Map<HashedId8, Certificate> trustStore, boolean entireChain) throws IllegalArgumentException,
            InvalidCertificateException, NoSuchAlgorithmException;

    /**
     * Method that verifies and validates all permissions on the build certificate chain.
     * <p>
     *     The method will build a chain for the certificate from the set of known certificates
     *     and the trust anchors.
     * </p>
     *
     *
     * For each certificate in the built chain it will check.
     * <ul>
     *     <li>Signature verifies</li>
     *     <li>Certificates validity</li>
     *     <li>Region matches</li>
     *     <li>App Permissions/Cert Issue Permissions</li>
     * </ul>
     * <p>
     *   <b>The method does not currently check revocation information.</b>
     * </p>
     * <p>
     *   <b>Permissions is only checked that it is consistent upwards in the chain. It does not check a specific permission</b>
     * </p>
     *
     * @param certificate the certificate to verify and validate
     * @param checkDate the date to check validity of certificate chain against.
     * @param checkRegion the region to check against, if null is region check skipped.
     * @param targetEndEntityType the type of end entity tree to check.
     * @param chainLengthIndex index parameter send to retrieve the correct group permissions from certificate. If validating chain that starts with end
     *                         entity certificate should chainLengthIndex be 0, if certificate chain starts with issuer of end entity certificate it should
     *                         be 1 and so on incremented up to root certificate in chain.
     * @param certStore a certstore that contains all intermediate CA certificates that is needed to build the chain.
     * @param trustStore a certstore of root ca certificates that are trusted.
     * @param entireChain if entireChain should be validated or only first certificate in chain.
     * @throws IllegalArgumentException if one of the parameters where invalid.
     * @throws InvalidCertificateException if one of the certificate in the build certificate chain was invalid.
     * @throws NoSuchAlgorithmException if use hash algorithm isn't supported by the system.
     */
    void verifyAndValidate(Certificate certificate, Date checkDate, GeographicRegion checkRegion,
                           EndEntityType targetEndEntityType, int chainLengthIndex,
                           Map<HashedId8, Certificate> certStore,
                           Map<HashedId8, Certificate> trustStore, boolean entireChain)
            throws IllegalArgumentException, InvalidCertificateException, NoSuchAlgorithmException;

    /**
     * Method that verifies and validates all permissions on a known certificate chain data. The
     * end entity certificate should be in position 0 and root certificate last.
     * <p>
     *     The method will build a chain for the certificate from the set of known certificates
     *     and the trust anchors.
     * </p>
     *
     *
     * For each certificate in the built chain it will check.
     * <ul>
     *     <li>Signature verifies</li>
     *     <li>Certificates validity</li>
     *     <li>Region matches</li>
     *     <li>App Permissions/Cert Issue Permissions</li>
     * </ul>
     * <p>
     *   <b>The method does not currently check revocation information.</b>
     * </p>
     * <p>
     *   <b>Permissions is only checked that it is consistent upwards in the chain. It does not check a specific permission</b>
     * </p>
     *
     * @param certificateChain the certificate chain to verify and validate. The
     * end entity certificate should be in position 0 and root certificate last.
     * @param checkDate the date to check validity of certificate chain against.
     * @param checkRegion the region to check against, if null is region check skipped.
     * @param targetEndEntityType the type of end entity tree to check.
     * @param entireChain if entireChain should be validated or only first certificate in chain.
     * @throws IllegalArgumentException if one of the parameters where invalid.
     * @throws InvalidCertificateException if one of the certificate in the build certificate chain was invalid.
     * @throws NoSuchAlgorithmException if use hash algorithm isn't supported by the system.
     */
    void verifyAndValidate(Certificate[] certificateChain, Date checkDate, GeographicRegion checkRegion,
                           EndEntityType targetEndEntityType, boolean entireChain) throws IllegalArgumentException,
            InvalidCertificateException, NoSuchAlgorithmException;


    /**
     * Method that verifies and validates all permissions on a known certificate chain data. The
     * end entity certificate should be in position 0 and root certificate last.
     * <p>
     *     The method will build a chain for the certificate from the set of known certificates
     *     and the trust anchors.
     * </p>
     *
     *
     * For each certificate in the built chain it will check.
     * <ul>
     *     <li>Signature verifies</li>
     *     <li>Certificates validity</li>
     *     <li>Region matches</li>
     *     <li>App Permissions/Cert Issue Permissions</li>
     * </ul>
     * <p>
     *   <b>The method does not currently check revocation information.</b>
     * </p>
     * <p>
     *   <b>Permissions is only checked that it is consistent upwards in the chain. It does not check a specific permission</b>
     * </p>
     *
     * @param certificateChain the certificate chain to verify and validate. The
     * end entity certificate should be in position 0 and root certificate last.
     * @param checkDate the date to check validity of certificate chain against.
     * @param checkRegion the region to check against, if null is region check skipped.
     * @param targetEndEntityType the type of end entity tree to check.
     * @param chainLengthIndex index parameter send to retrieve the correct group permissions from certificate. If validating chain that starts with end
     *                         entity certificate should chainLengthIndex be 0, if certificate chain starts with issuer of end entity certificate it should
     *                         be 1 and so on incremented up to root certificate in chain.
     * @param entireChain if entireChain should be validated or only first certificate in chain.
     * @throws IllegalArgumentException if one of the parameters where invalid.
     * @throws InvalidCertificateException if one of the certificate in the build certificate chain was invalid.
     * @throws NoSuchAlgorithmException if use hash algorithm isn't supported by the system.
     */
    void verifyAndValidate(Certificate[] certificateChain, Date checkDate, GeographicRegion checkRegion,
                           EndEntityType targetEndEntityType, int chainLengthIndex, boolean entireChain) throws IllegalArgumentException,
            InvalidCertificateException, NoSuchAlgorithmException;
}
