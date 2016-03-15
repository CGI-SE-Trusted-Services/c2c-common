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


import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.common.BaseStructSpec;
import org.certificateservices.custom.c2x.its.datastructs.basic.CircularRegion
import org.certificateservices.custom.c2x.its.datastructs.basic.Duration
import org.certificateservices.custom.c2x.its.datastructs.basic.EccPoint;
import org.certificateservices.custom.c2x.its.datastructs.basic.EccPointType;
import org.certificateservices.custom.c2x.its.datastructs.basic.EncryptionParameters
import org.certificateservices.custom.c2x.its.datastructs.basic.GeographicRegion
import org.certificateservices.custom.c2x.its.datastructs.basic.HashedId3
import org.certificateservices.custom.c2x.its.datastructs.basic.HashedId8
import org.certificateservices.custom.c2x.its.datastructs.basic.IntX
import org.certificateservices.custom.c2x.its.datastructs.basic.PublicKey
import org.certificateservices.custom.c2x.its.datastructs.basic.PublicKeyAlgorithm;
import org.certificateservices.custom.c2x.its.datastructs.basic.RegionType;
import org.certificateservices.custom.c2x.its.datastructs.basic.SignerInfo
import org.certificateservices.custom.c2x.its.datastructs.basic.SymmetricAlgorithm;
import org.certificateservices.custom.c2x.its.datastructs.basic.ThreeDLocation
import org.certificateservices.custom.c2x.its.datastructs.basic.Time64
import org.certificateservices.custom.c2x.its.datastructs.basic.Time64WithStandardDeviation
import org.certificateservices.custom.c2x.its.datastructs.basic.TwoDLocation
import org.certificateservices.custom.c2x.its.datastructs.basic.Duration.Unit;
import org.certificateservices.custom.c2x.its.datastructs.basic.Time32
import org.certificateservices.custom.c2x.its.datastructs.msg.Payload;

import spock.lang.IgnoreRest;
import spock.lang.Specification;
import spock.lang.Unroll;
import static org.certificateservices.custom.c2x.its.datastructs.msg.PayloadType.*;

/**
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class PayloadSpec extends BaseStructSpec {
	
	Payload plse = new Payload();
	Payload ple = new Payload(encrypted, new byte[30]);
	
	def "Verify the constructors and getters"(){
		expect:
		plse.payloadType == signed_external
		plse.data == null
		
		ple.payloadType == encrypted
		ple.data.length == 30
		
		new Payload(signed_external, null).data == null
		when: 
		new Payload(encrypted, null);
		then:
		thrown IllegalArgumentException

	}

	
	def "Verify serialization"(){
		expect:
		serializeToHex(plse) == "03"
		serializeToHex(ple) == "021e000000000000000000000000000000000000000000000000000000000000"				
	}
	
	def "Verify deserialization"(){
		setup:		
		Payload plse2 = deserializeFromHex(new Payload(),"03")
		Payload ple2 = deserializeFromHex(new Payload(),"021e000000000000000000000000000000000000000000000000000000000000")
		
		expect:
		plse2.payloadType == signed_external
		plse2.data == null
		
		ple2.payloadType == encrypted
		ple2.data.length == 30
	}

	
	def "Verify toString"(){
		expect:
		plse.toString() == "Payload [payloadType=signed_external]"
		ple.toString() == "Payload [payloadType=encrypted, data=[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]]"
	}
}

