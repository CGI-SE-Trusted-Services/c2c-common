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
package org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert;

import org.certificateservices.custom.c2x.asn1.coer.COEREnumerationType;

/**
 * This enumerated type indicates whether a certificate is explicit or implicit.
 * <p>
 *     <b>Critical information fields:</b>If present, this is a critical information field as defined in 5.2.5. An
 * implementation that does not recognize the indicated CHOICE for this type when verifying a signed SPDU
 * shall indicate that the signed SPDU is invalid.
 * </p>
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public enum CertificateType implements COEREnumerationType {
	explicit,
	implicit;

}
