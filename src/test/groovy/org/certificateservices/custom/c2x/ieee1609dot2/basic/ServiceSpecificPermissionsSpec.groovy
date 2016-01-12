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
package org.certificateservices.custom.c2x.ieee1609dot2.basic

import java.awt.Choice;

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.asn1.coer.COEREncodeHelper;
import org.certificateservices.custom.c2x.asn1.coer.COEROctetStream;
import org.certificateservices.custom.c2x.common.BaseStructSpec;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Duration.DurationChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.EccP256CurvePoint.EccP256CurvePointChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.PublicVerificationKey.PublicVerificationKeyChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.ServiceSpecificPermissions.ServiceSpecificPermissionsChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Signature.SignatureChoices;
import org.certificateservices.custom.c2x.its.crypto.DefaultCryptoManagerParams;

import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for ServiceSpecificPermissions
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class ServiceSpecificPermissionsSpec extends BaseStructSpec {
	
	byte[] x = new BigInteger(123).toByteArray()
	
	@Unroll
	def "Verify that ServiceSpecificPermissions is correctly encoded for type #choice"(){
		when:
		def p = new ServiceSpecificPermissions(choice, x)
		
		then:
		serializeToHex(p) == encoding
		
		when:
		ServiceSpecificPermissions p2 = deserializeFromHex(new ServiceSpecificPermissions(), encoding)
		
		then:
		p2.getData() == x
		p2.choice == choice
		p2.type == choice
		
		where:
		choice                                            | encoding   
		ServiceSpecificPermissionsChoices.opaque          | "80017b"   
		    

		
	}
	

	
	def "Verify toString"(){
		expect:
		new ServiceSpecificPermissions(ServiceSpecificPermissionsChoices.opaque, x).toString() == "ServiceSpecificPermissions [opaque=[7b]]"
	}
	

}
