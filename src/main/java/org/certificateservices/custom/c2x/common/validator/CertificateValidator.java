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

import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId8;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate;

import java.io.IOException;
import java.security.SignatureException;
import java.util.Map;

/**
 * TODO
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
     *
     * @param certificate the certificate to verify and validate
     * @param certStore
     * @param trustStore
     * @throws IllegalArgumentException
     * @throws InvalidCertificateException
     */
    // TODO CRLS
    void verifyAndValidate(Certificate certificate, Map<HashedId8, Certificate> certStore, Map<HashedId8, Certificate> trustStore) throws IllegalArgumentException, InvalidCertificateException;
}
