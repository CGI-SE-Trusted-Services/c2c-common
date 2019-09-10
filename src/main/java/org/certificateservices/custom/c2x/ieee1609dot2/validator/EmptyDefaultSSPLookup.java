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
 * Implementation of DefaultSSPLookup that doesn't contain any default values for any SSP or SSPRanges and
 * always returns null. Used in PKIs where no default SSP values are defined.
 *
 * @author Philip Vendil, p.vendil@cgi.com
 */
public class EmptyDefaultSSPLookup implements DefaultSSPLookup {

    /**
     * Method that always returns null as default ServiceSpecificPermissions.
     *
     * @param psid the PSID to lookup default ssp range for.
     * @return the default ServiceSpecificPermissions defined for given Psid or null.
     */
    @Override
    public ServiceSpecificPermissions getDefaultSSP(Psid psid) {
        return null;
    }

    /**
     * Method that always returns null as default SspRange.
     *
     * @param psid the PSID to lookup default ssp range for.
     * @return the default SspRange defined for given psid or null.
     */
    @Override
    public SspRange getDefaultSSPRange(Psid psid) {
        return null;
    }
}
