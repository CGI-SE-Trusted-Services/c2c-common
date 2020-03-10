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
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.GeographicRegion;

/**
 * Interface for implementing
 *
 * @author Philip Vendil, p.vendil@cgi.com
 */
public interface RegionValidator {

    /**
     * Method to verify that the region in certificate matches the requirement in the
     * issuer certificate. If certificate is self-signed it ignore the certificate.
     *
     * @param checkRegion the expected region to validate the certificate for.
     * @param certificateChain the certificate to verify region in, end entity certificate first and root cert last.
     *
     * @throws InvalidCertificateException if region in given certificate was invalid.
     * @throws BadArgumentException if other argument was invalid not related to the region in the certificate.
     */
    void validateRegion(GeographicRegion checkRegion, Certificate[] certificateChain) throws BadArgumentException, InvalidCertificateException;
}

