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
package org.certificateservices.custom.c2x.ieee1609dot2.validator;

import org.certificateservices.custom.c2x.common.validator.RegionValidator;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.GeographicRegion;

/**
 * Abstract base class of region validators containing in common help methods.
 *
 * @author Philip Vendil, p.vendil@cgi.com
 */
public abstract class BaseRegionValidator implements RegionValidator {


    /**
     * Help method to get the GeographicRegion from a certificate
     * @param certificate the certificate to fetch region from
     * @return the region field in the certificate.
     */
    protected GeographicRegion getRegion(org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate certificate){
        return certificate.getToBeSigned().getRegion();
    }
}
