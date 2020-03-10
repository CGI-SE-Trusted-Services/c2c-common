/************************************************************************
 *                                                                       *
 *  Certificate Service - Car2Car Core                                  *
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
import java.util.Date;

/**
 * Interface for validating the time of a certificate or certificate chain
 *
 * @author Philip Vendil, p.vendil@cgi.com
 */
public interface TimeValidator {

    /**
     * Method to verify that the given certificates are valid against the specified time.
     *
     * @param currentTime the expected time to verify the certificate against.
     * @param certificateChain the certificate to verify region in, end entity certificate first and root cert last.
     * @param entireChain if entireChain should be validated or only first certificate in chain.
     * @throws InvalidCertificateException if the given certificate chain was invalid for the specified time.
     * @throws BadArgumentException if other argument was invalid when validation the certificate.
     */
    void validateTime(Date currentTime, Certificate[] certificateChain, boolean entireChain) throws BadArgumentException, InvalidCertificateException;
}
