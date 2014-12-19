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
import org.certificateservices.custom.c2x.its.datastructs.BaseStructSpec;
import org.certificateservices.custom.c2x.its.datastructs.basic.EccPoint;
import org.certificateservices.custom.c2x.its.datastructs.basic.EccPointType;
import org.certificateservices.custom.c2x.its.datastructs.basic.PublicKeyAlgorithm;

import spock.lang.IgnoreRest;
import spock.lang.Specification;
import spock.lang.Unroll;

import static org.certificateservices.custom.c2x.its.datastructs.basic.EccPointType.*;

/**
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class EccPointSpec extends BaseStructSpec {
	
	def compressedData1 = new byte[33]
	def compressedData2 = new byte[33]
	
	def setup(){
		compressedData1[0] = 02
		compressedData2[0] = 03
	}
	
	def "Verify constructors and getters and setters"(){
		when:
		EccPoint p = new EccPoint(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256);
		then:
		p.publicKeyAlgorithm == PublicKeyAlgorithm.ecdsa_nistp256_with_sha256
		p.eccPointType == null
		p.x == null
		p.y == null;
		when:
		p = new EccPoint(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, EccPointType.x_coordinate_only, new BigInteger(1));
		then:
		p.publicKeyAlgorithm == PublicKeyAlgorithm.ecdsa_nistp256_with_sha256
		p.eccPointType ==  EccPointType.x_coordinate_only
		p.x.toInteger() == 1
		p.y == null
		when:
		p = new EccPoint(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, compressedData1);
		then:
		p.publicKeyAlgorithm == PublicKeyAlgorithm.ecdsa_nistp256_with_sha256
		p.eccPointType ==  EccPointType.compressed_lsb_y_0
		p.x  == null
		p.y == null
		p.compressedEncoding.length == 33
		when:
		p = new EccPoint(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256,compressedData2);
		then:
		p.publicKeyAlgorithm == PublicKeyAlgorithm.ecdsa_nistp256_with_sha256
		p.eccPointType ==  EccPointType.compressed_lsb_y_1
		p.x  == null
		p.y == null
		p.compressedEncoding.length == 33
		when:
		p = new EccPoint(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, EccPointType.uncompressed, new BigInteger(1), new BigInteger(2));
		then:
		p.publicKeyAlgorithm == PublicKeyAlgorithm.ecdsa_nistp256_with_sha256
		p.eccPointType ==  EccPointType.uncompressed
		p.x.toInteger() == 1
		p.y.toInteger() == 2
		when:
		p = new EccPoint(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, new byte[32]);
		then:
		thrown IllegalArgumentException
		when:
		p = new EccPoint(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256,  new byte[34]);
		then:
		thrown IllegalArgumentException
	}
	
	@Unroll
	def "Verify that writeFixedFieldSizeKey writes to byte array with correct fieldsize"(){
		setup:
		EccPoint p = new EccPoint(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256);
		ByteArrayOutputStream  baos = new ByteArrayOutputStream();
		DataOutputStream dos = new DataOutputStream(baos);
		when:
		p.writeFixedFieldSizeKey(dos, new BigInteger(Hex.decode(keyValue)));
		byte[] data =  baos.toByteArray()
		then:
		data.length == 32
		new String(Hex.encode(data)) == expectedBytes
		where:
		keyValue                                                           | expectedBytes
		"00"                                                               | "0000000000000000000000000000000000000000000000000000000000000000"
		"01"                                                               | "0000000000000000000000000000000000000000000000000000000000000001"
		"FF00FF"                                                           | "0000000000000000000000000000000000000000000000000000000000ff00ff"
		"FF000000000000000000000000000000000000000000000000000000000000ff" | "ff000000000000000000000000000000000000000000000000000000000000ff"

	}
	
	@Unroll
	def "Verify that readFixedFieldSizeKey reads from byte array with correct fieldsize"(){
		setup:
		EccPoint p = new EccPoint(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256);
		ByteArrayInputStream  bais = new ByteArrayInputStream(Hex.decode(keyValueInBytes));
		DataInputStream dis = new DataInputStream(bais);
		when:
		BigInteger v = p.readFixedFieldSizeKey(dis);
		byte[] data =  v.toByteArray();
		then:
		v.toString(16) == expectedValue
		where:
		expectedValue                                                        | keyValueInBytes
		"0"                                                                  | "0000000000000000000000000000000000000000000000000000000000000000"
		"1"                                                                  | "0000000000000000000000000000000000000000000000000000000000000001"
		"ff00ff"                                                             | "0000000000000000000000000000000000000000000000000000000000ff00ff"
		"ff000000000000000000000000000000000000000000000000000000000000ff"   | "ff000000000000000000000000000000000000000000000000000000000000ff"

	}
	

	def "Verify serialization of EccPoint"(){
		when: "Verify simple x_coordinate_only serialization"
		String result = serializeToHex(new EccPoint(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, EccPointType.x_coordinate_only, new BigInteger(1)));
		then:
		result.length() /2 == 33;
		result.substring(0,2) == "00" // EccPointType is correct
		result.substring(2) == "0000000000000000000000000000000000000000000000000000000000000001" // X Value have been serialized.
		when: "Serialization of uncompressed"
		result = serializeToHex(new EccPoint(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, EccPointType.uncompressed, new BigInteger(1), new BigInteger(2)));
	    then:
		result.length() /2 == 65;
		result.substring(0,2) == "04" // EccPointType is correct
		result.substring(2,66) == "0000000000000000000000000000000000000000000000000000000000000001" // X Value have been serialized.
		result.substring(66) == "0000000000000000000000000000000000000000000000000000000000000002" // Y Value have been serialized.
		when: "Verify simple x_coordinate_only serialization"
		result = serializeToHex(new EccPoint(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256,  compressedData1));
		then:
		result.length() /2 == 33;
		result.substring(0,2) == "02" // EccPointType is correct
		result.substring(2) == "0000000000000000000000000000000000000000000000000000000000000000" // X Value have been serialized.
	}
	
	def "Verify deserialization of EccPoint"(){
		when: "Verify simple x_coordinate_only deserialization"                                   // ecc point type // x key value   
		EccPoint result = deserializeFromHex(new EccPoint(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256), "00" + "0000000000000000000000000000000000000000000000000000000000000001");
		then:
		result.publicKeyAlgorithm == PublicKeyAlgorithm.ecdsa_nistp256_with_sha256
		result.eccPointType == EccPointType.x_coordinate_only
		result.x.toInteger() == 1
		result.y == null
		when: "Deserialization of uncompressed"                                          // ecc point type // x key value                                                    // y key value
		result = deserializeFromHex(new EccPoint(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256), "04" + "0000000000000000000000000000000000000000000000000000000000000001" + "0000000000000000000000000000000000000000000000000000000000000002");
		then:
		result.publicKeyAlgorithm == PublicKeyAlgorithm.ecdsa_nistp256_with_sha256
		result.eccPointType == EccPointType.uncompressed
		result.x.toInteger() == 1
		result.y.toInteger() == 2
		when: "Verify  compressed deserialization"                                   // ecc point type // x key value
		result = deserializeFromHex(new EccPoint(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256), "02" + "0000000000000000000000000000000000000000000000000000000000000001");
		then:
		result.publicKeyAlgorithm == PublicKeyAlgorithm.ecdsa_nistp256_with_sha256
		result.eccPointType == EccPointType.compressed_lsb_y_0
		result.x == null
		result.y == null
		result.compressedEncoding.length == 33
		result.compressedEncoding[0] == 2
		
	}
	

	def "Verify hashCode and equals"(){
		setup:
		
		def o1  = new EccPoint(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, EccPointType.uncompressed, new BigInteger(1), new BigInteger(2));
		def o2  = new EccPoint(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, EccPointType.uncompressed, new BigInteger(1), new BigInteger(2));
		def o3  = new EccPoint(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, EccPointType.uncompressed, new BigInteger(1), null);
		def o4  = new EccPoint(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, EccPointType.uncompressed, new BigInteger(2), new BigInteger(2));
		def o5  = new EccPoint(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, EccPointType.uncompressed, null, new BigInteger(2));
		def o6  = new EccPoint(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, EccPointType.x_coordinate_only, new BigInteger(1), new BigInteger(2));
		def o7  = new EccPoint(PublicKeyAlgorithm.ecies_nistp256, EccPointType.uncompressed, new BigInteger(1), new BigInteger(2));
		def o8  = new EccPoint(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, compressedData1);
		expect:
		o1 == o2
		o1 != o3
		o1 != o4
		o1 != o5 
		o1 != o6
		o1 != o7
		o1 != o8
		o1.hashCode() == o2.hashCode()
		o1.hashCode() != o3.hashCode()
		o1.hashCode() != o4.hashCode()
		o1.hashCode() != o5.hashCode()
		o1.hashCode() != o6.hashCode()
		o1.hashCode() != o7.hashCode()
		o1.hashCode() != o8.hashCode()
	}
	
	def "Verify toString"(){
		expect:
		 new EccPoint(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, EccPointType.uncompressed, new BigInteger(1), new BigInteger(2)).toString() == "EccPoint [publicKeyAlgorithm=ecdsa_nistp256_with_sha256, x=1, y=2, eccPointType=uncompressed]"		 
		 new EccPoint(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, EccPointType.x_coordinate_only, new BigInteger(1)).toString() == "EccPoint [publicKeyAlgorithm=ecdsa_nistp256_with_sha256, x=1, eccPointType=x_coordinate_only]"
		 new EccPoint(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, compressedData1).toString() == "EccPoint [publicKeyAlgorithm=ecdsa_nistp256_with_sha256, compressedEncoding=[2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], eccPointType=compressed_lsb_y_0]"
	}

}
