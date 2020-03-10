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

import org.certificateservices.custom.c2x.common.BadArgumentException;
import org.certificateservices.custom.c2x.common.Certificate;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.EndEntityType;

/**
 * Interface for verifying that all permissions are consistent with the issuers in the chain.
 *
 * @author Philip Vendil, p.vendil@cgi.com
 */
public interface PermissionValidator {

    /**
     * Method to validate permissions in a certificate chain that starts with an end entity certificate. It will check
     * all permissions set in the certificate for the given end entity type.
     *
     * @param targetEndEntityType the target end entity type to validate.
     * @param certificateChain the certificate chain with end entity certificate first. Must be at least length of 2
     * @param entireChain if entireChain should be validated or only first certificate in chain.
     * @throws BadArgumentException if one of the specified parameters was invalid.
     * @throws InvalidCertificateException if certificate chain contained invalid permissions.
     */
    void checkPermissions(EndEntityType targetEndEntityType, Certificate[] certificateChain, boolean entireChain) throws BadArgumentException, InvalidCertificateException;

    /**
     * Special use-case method to validate permissions in a certificate chain that starts with a ca certificate. It will check
     * all permissions set in the certificate for the given end entity type.
     *
     * @param targetEndEntityType the target end entity type to validate.
     * @param chainLengthIndex index parameter send to retrieve the correct group permissions from certificate. If validating chain that starts with end
     *                         entity certificate should chainLengthIndex be 0, if certificate chain starts with issuer of end entity certificate it should
     *                         be 1 and so on incremented up to root certificate in chain.
     * @param certificateChain the certificate chain with end entity certificate first. Must be at least length of 2
     * @param entireChain if entireChain should be validated or only first certificate in chain.
     * @throws BadArgumentException if one of the specified parameters was invalid.
     * @throws InvalidCertificateException if certificate chain contained invalid permissions.
     */
    void checkPermissions(EndEntityType targetEndEntityType, int chainLengthIndex, Certificate[] certificateChain, boolean entireChain) throws BadArgumentException, InvalidCertificateException;
}
