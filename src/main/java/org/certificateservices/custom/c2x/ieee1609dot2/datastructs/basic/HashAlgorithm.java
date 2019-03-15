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
package org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic;

import org.certificateservices.custom.c2x.asn1.coer.COEREnumerationType;
import org.certificateservices.custom.c2x.common.crypto.Algorithm;
import org.certificateservices.custom.c2x.common.crypto.AlgorithmIndicator;

/**
 * This structure identifies a hash algorithm. SHA-256 as specified in 5.3.3. The value sha384 indicates SHA-384 as specified in 5.3.3.
 * 
 * <b>Critical information fields: </b>This is a critical information field as defined in 5.2.5. An implementation that does not recognize 
 * the enumerated value of this type in a signed SPDU when verifying a signed SPDU shall indicate that the signed SPDU is invalid.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public enum HashAlgorithm implements COEREnumerationType, AlgorithmIndicator {
	sha256(Algorithm.Hash.sha256),
	sha384(Algorithm.Hash.sha384);

	private Algorithm.Hash relatedHash;

	HashAlgorithm(Algorithm.Hash relatedHash){
		this.relatedHash = relatedHash;
	}

	@Override
	public Algorithm getAlgorithm() {
		return new Algorithm(null,null,null,relatedHash);
	}
	
	
}
