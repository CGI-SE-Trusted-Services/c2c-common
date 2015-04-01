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



import org.certificateservices.custom.c2x.its.datastructs.basic.SymmetricAlgorithm;

import spock.lang.Specification;
import spock.lang.Unroll;

import static org.certificateservices.custom.c2x.its.datastructs.basic.SymmetricAlgorithm.*;

/**
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class SymmetricAlgorithmSpec extends Specification{
	
	@Unroll
	def "Verify that #symmetricAlgorithm has bytevalue #bytevalue"(){
		expect:
		symmetricAlgorithm.byteValue instanceof Integer
		symmetricAlgorithm.byteValue == bytevalue
		symmetricAlgorithm.keyLength == keyLength
		where:
		symmetricAlgorithm             | bytevalue  | keyLength
		aes_128_ccm                    | 0          | 16

	}
	
	@Unroll
	def "Verify that SymmetricAlgorithm.getByValue returns #symmetricAlgorithm for #bytevalue"(){
		expect:
		SymmetricAlgorithm.getByValue( bytevalue) == symmetricAlgorithm
		where:
		symmetricAlgorithm             | bytevalue
		aes_128_ccm                    | 0

	}

}
