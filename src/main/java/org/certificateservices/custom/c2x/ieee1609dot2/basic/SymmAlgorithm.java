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
package org.certificateservices.custom.c2x.ieee1609dot2.basic;

import org.certificateservices.custom.c2x.asn1.coer.COEREnumerationType;
import org.certificateservices.custom.c2x.common.crypto.Algorithm;
import org.certificateservices.custom.c2x.common.crypto.AlgorithmIndicator;

/**
 * This enumerated value indicates supported symmetric algorithms. The only symmetric algorithm supported in this version of this standard is AES-CCM as specified in 5.3.8.
 * <p>
 * <b>Critical information fields:</b> 
 * If present, this is a critical information field as defined in 5.2.5. An implementation that does not recognize the indicated enumerated value for this type when 
 * verifying a signed SPDU shall indicate that the signed SPDU is invalid.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public enum SymmAlgorithm implements COEREnumerationType, AlgorithmIndicator {
	aes128Ccm;
	
	@Override
	public Algorithm getAlgorithm() {
		return new Algorithm(Algorithm.Symmetric.aes128Ccm, null, null, null);
	}
	
}
