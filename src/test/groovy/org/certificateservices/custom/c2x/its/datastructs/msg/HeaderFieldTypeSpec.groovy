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
package org.certificateservices.custom.c2x.its.datastructs.msg



import org.certificateservices.custom.c2x.its.datastructs.msg.HeaderFieldType;

import spock.lang.Specification;
import spock.lang.Unroll;
import static org.certificateservices.custom.c2x.its.datastructs.msg.HeaderFieldType.*;


/**
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class HeaderFieldTypeSpec extends Specification{
	
	@Unroll
	def "Verify that #type has bytevalue #bytevalue"(){
		expect:
		type.getByteValue(1) == ver1Value
		type.getByteValue(2) == ver2Value
		if(type != signer_info){
			assert type.getOrder(1) == ver1Value
		    assert type.getOrder(2) == ver2Value
		}else{
		    assert type.getOrder(1) == Integer.MIN_VALUE
		    assert type.getOrder(2) == Integer.MIN_VALUE
		}
		where:
		type                             | ver1Value           | ver2Value              
		generation_time                  | 0                   | 0                      
		generation_time_confidence       | 1                   | 1
		expiration                       | 2                   | 2
		generation_location              | 3                   | 3
		request_unrecognized_certificate | 4                   | 4
		message_type                     | 5                   | INVALID_BYTE_VALUE
		its_aid                          | INVALID_BYTE_VALUE  | 5
		signer_info                      | 128                 | 128
		recipient_info                   | 129                 | 130
		encryption_parameters            | 130                 | 129

	}
	

	
	@Unroll
	def "Verify that HeaderFieldType.getByValue returns #type for #bytevalue"(){
		expect:
		HeaderFieldType.getByValue(1, ver1Value) == type
		HeaderFieldType.getByValue(2, ver2Value) == type
		where:
		type                             | ver1Value           | ver2Value
		generation_time                  | 0                   | 0
		generation_time_confidence       | 1                   | 1
		expiration                       | 2                   | 2
		generation_location              | 3                   | 3
		request_unrecognized_certificate | 4                   | 4
		message_type                     | 5                   | INVALID_BYTE_VALUE
		its_aid                          | INVALID_BYTE_VALUE  | 5
		signer_info                      | 128                 | 128
		recipient_info                   | 129                 | 130
		encryption_parameters            | 130                 | 129

	}

}
