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
package org.certificateservices.custom.c2x.asn1.coer

import org.bouncycastle.util.encoders.Hex
import org.certificateservices.custom.c2x.common.BaseStructSpec
import spock.lang.Unroll

/**
 * Unit tests for COEROctetStream
 * @author Philip Vendil
 */
class COEROctetStreamSpec extends BaseStructSpec {


	
	@Unroll
	def "Verify that COEROctetStream with #encoded encoded and decoded #encoded generates a value with lower bound #lowerbound and upper bound #upperbound"(){
		when:
		COEROctetStream coerOctedStream = new COEROctetStream(Hex.decode(data), lowerbound, upperbound)
		then:
		serializeToHex(coerOctedStream) == encoded
		
		when:
		coerOctedStream = deserializeFromHex(new COEROctetStream(lowerbound, upperbound), encoded) as COEROctetStream
		then:
		new String(Hex.encode(coerOctedStream.data)) == data
		
		where:
		encoded                                     | data                    | lowerbound     | upperbound                  
		"00"                                        | "00"                    | 1              | 1
		"0df3acf45678"                              | "0df3acf45678"          | 6              | 6
		"060df3acf45678"                            | "0df3acf45678"          | 5              | 6
		"060df3acf45678"                            | "0df3acf45678"          | 6              | 7
		"060df3acf45678"                            | "0df3acf45678"          | 5              | null
		"060df3acf45678"                            | "0df3acf45678"          | null           | 7
		"060df3acf45678"                            | "0df3acf45678"          | null           | null
	}


	def "Verify that constuctor and getter"(){
		expect:
		new COEROctetStream(4,5).getLowerBound() == 4
		new COEROctetStream(4,5).getUpperBound() == 5
		new COEROctetStream([0x0a] as byte[]).getData().length == 1
		new COEROctetStream([0x0a] as byte[],1,5).getLowerBound() == 1
		new COEROctetStream([0x0a] as byte[],1,5).getUpperBound() == 5
		new COEROctetStream([0x0a,0x0b] as byte[],1,5).getData().length == 2
	}
	
	def "Verify that constructor throws IOException if data is out of bounds"(){
		when:
		new COEROctetStream([0x0a,0x0b] as byte[], 3,5)
		then:
		thrown IOException
		when:
		new COEROctetStream([0x0a,0x0b] as byte[], 1,1)
		then:
		thrown IOException
	}
	
	def "Verify equals and hashcode"(){
		setup:
		COEROctetStream first = new COEROctetStream([0x0a] as byte[])
		COEROctetStream sameAsFirst = new COEROctetStream([0x0a] as byte[])
		COEROctetStream second = new COEROctetStream([0x0b] as byte[])
		
		expect:
		first != second
		first == sameAsFirst
		first.hashCode() != second.hashCode()
		first.hashCode() == sameAsFirst.hashCode()
	}


	def "Verify toString"(){
		expect:
		new COEROctetStream([0x0b] as byte[]).toString() == "COEROctetStream [data=0b]"
	}
	

}
