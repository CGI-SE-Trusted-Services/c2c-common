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
package org.certificateservices.custom.c2x.ieee1609dot2.datastructs.crl.ssp;

import org.certificateservices.custom.c2x.asn1.coer.COEREnumerationType;

/**
 * This type is used to determine the validity of the cracaId field in the CrlContents structure.
 * <ul>
 *     <li>If this takes the value isCraca, the cracaId field in the CrlContents structure is invalid unless
 * it indicates the certificate that signs the CRL.</li>
 *     <li>If this takes the value issuer, the isCracaDelegate field in the CrlContents structure is invalid
 * unless it indicates the certificate that issued the certificate that signs the CRL.</li>
 * </ul>
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public enum CracaType implements COEREnumerationType {
	isCraca,
	issuerIsCraca;	
}
