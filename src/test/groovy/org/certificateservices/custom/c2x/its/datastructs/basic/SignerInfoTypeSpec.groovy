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



import org.certificateservices.custom.c2x.its.datastructs.basic.SignerInfoType;

import spock.lang.Specification;
import spock.lang.Unroll;

import static org.certificateservices.custom.c2x.its.datastructs.basic.SignerInfoType.*;

/**
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class SignerInfoTypeSpec extends Specification{
	
	@Unroll
	def "Verify that #signerInfoType has bytevalue #bytevalue"(){
		expect:
		signerInfoType.byteValue instanceof Integer
		signerInfoType.byteValue == bytevalue
		where:
		signerInfoType                           | bytevalue
		self                                     | 0
		certificate_digest_with_ecdsap256        | 1
		certificate                              | 2
		certificate_chain                        | 3
		certificate_digest_with_other_algorithm  | 4
	}
	
	@Unroll
	def "Verify that SignerInfoType.getByValue returns #signerInfoType for #bytevalue"(){
		expect:
		SignerInfoType.getByValue( bytevalue) == signerInfoType
		where:
		signerInfoType                           | bytevalue
		self                                     | 0
		certificate_digest_with_ecdsap256        | 1
		certificate                              | 2
		certificate_chain                        | 3
		certificate_digest_with_other_algorithm  | 4
		

	}

}
