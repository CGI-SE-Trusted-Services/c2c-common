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
package org.certificateservices.custom.c2x.its.datastructs.basic


import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.common.BaseStructSpec;
import org.certificateservices.custom.c2x.its.datastructs.basic.EncryptionParameters;
import org.certificateservices.custom.c2x.its.datastructs.basic.SymmetricAlgorithm;

import spock.lang.IgnoreRest;
import spock.lang.Specification;
import spock.lang.Unroll;
import static org.certificateservices.custom.c2x.its.datastructs.basic.EccPointType.*;

/**
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class EncryptionParametersSpec extends BaseStructSpec {
	
	def "Verify constructors and getters and setters"(){
		when:
		EncryptionParameters ep = new EncryptionParameters(SymmetricAlgorithm.aes_128_ccm, new byte[12]);
		then:
		ep.symmetricAlgorithm == SymmetricAlgorithm.aes_128_ccm
		ep.nounce.length == 12		
		when: 
		ep = new EncryptionParameters(null, new byte[12]);
		then:
		thrown IllegalArgumentException
		when: 
		ep = new EncryptionParameters(SymmetricAlgorithm.aes_128_ccm, new byte[11]);
		then:
		thrown IllegalArgumentException
		when:
		ep = new EncryptionParameters(SymmetricAlgorithm.aes_128_ccm, new byte[13]);
		then:
		thrown IllegalArgumentException
		when:
		ep = new EncryptionParameters(SymmetricAlgorithm.aes_128_ccm, null);
		then:
		thrown IllegalArgumentException
	}

	byte[] testNounce = Hex.decode("11223344556677889900aabb");

	def "Verify serialization of EncryptionParameters"(){
		when: 
		String result = serializeToHex(new EncryptionParameters(SymmetricAlgorithm.aes_128_ccm, testNounce));
		then:
		result.length() /2 == 13;
		result.substring(0,2) == "00" // SymmetricAlgorithm is correct
		result.substring(2) == "11223344556677889900aabb" // nounce serialized.
		
	}
	
	def "Verify deserialization of EncryptionParameters"(){
		when:                                                                // SymmetricAlgorithm // nounce  
		EncryptionParameters result = deserializeFromHex(new EncryptionParameters(), "00" + "11223344556677889900aabb");
		then:
		result.symmetricAlgorithm == SymmetricAlgorithm.aes_128_ccm
		result.nounce == testNounce
	}
	
	def "Verify toString"(){
		expect:
		 new EncryptionParameters(SymmetricAlgorithm.aes_128_ccm, new byte[12]).toString() == "EncryptionParameters [symmetricAlgorithm=aes_128_ccm, nonce=[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]]"
	}

	

}
