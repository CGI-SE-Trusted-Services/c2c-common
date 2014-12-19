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
		type.byteValue instanceof Integer
		type.byteValue == bytevalue
		where:
		type                             | bytevalue
		generation_time                  | 0
		generation_time_confidence       | 1
		expiration                       | 2
		generation_location              | 3
		request_unrecognized_certificate | 4
		message_type                     | 5
		signer_info                      | 128
		recipient_info                   | 129
		encryption_parameters            | 130

	}
	
	@Unroll
	def "Verify that TrailerFieldType.getByValue returns #type for #bytevalue"(){
		expect:
		HeaderFieldType.getByValue( bytevalue) == type
		where:
		type                             | bytevalue
		generation_time                  | 0
		generation_time_confidence       | 1
		expiration                       | 2
		generation_location              | 3
		request_unrecognized_certificate | 4
		message_type                     | 5
		signer_info                      | 128
		recipient_info                   | 129
		encryption_parameters            | 130

	}

}
