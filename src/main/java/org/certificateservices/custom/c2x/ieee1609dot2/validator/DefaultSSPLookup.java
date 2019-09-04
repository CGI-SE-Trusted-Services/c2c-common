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

import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Psid;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.ServiceSpecificPermissions;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SspRange;

/**
 * Interface for implementations to lookup Default SSP Data for a specific SSP.
 * This is used for validating certificate where ssp data or ssp range data is omitted which means
 * default data should be used which is up to each SSP Owner to define.
 *
 * @author Philip Vendil, p.vendil@cgi.com
 */
public interface DefaultSSPLookup {

    /**
     * Method to return default ServiceSpecificPermissions for a specific Psid. If no default value exist
     * should null be returned.
     *
     * @param psid the PSID to lookup default ssp range for.
     * @return the default ServiceSpecificPermissions defined for given Psid or null.
     */
    ServiceSpecificPermissions getDefaultSSP(Psid psid);

    /**
     * Method to return default SspRange for a specific Psid. If no default value exist
     * should null be returned.
     *
     * @param psid the PSID to lookup default ssp range for.
     * @return the default SspRange defined for given psid or null.
     */
    SspRange getDefaultSSPRange(Psid psid);
}
