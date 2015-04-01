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



import org.certificateservices.custom.c2x.its.datastructs.msg.MessageType;

import spock.lang.Specification;
import spock.lang.Unroll;

import static org.certificateservices.custom.c2x.its.datastructs.msg.MessageType.*;
/**
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class MessageTypeSpec extends Specification{
	
	@Unroll
	def "Verify that #type has value #value and security profile"(){
		expect:		
		type.value == value
		type.securityProfile == security_profile
		where:
		type                             | value | security_profile
		CAM                              | 2     | 1
		DENM                             | 1     | 2


	}
	
	@Unroll
	def "Verify that SecurityProfile.getByValue returns #type for #value"(){
		expect:
		MessageType.getByValue( value) == type
		where:
		type                             | value
		CAM                              | 2
		DENM                             | 1

	}

}
