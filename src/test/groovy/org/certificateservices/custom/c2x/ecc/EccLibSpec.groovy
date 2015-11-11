package org.certificateservices.custom.c2x.ecc

import spock.lang.Specification;
import spock.lang.Unroll;

class EccLibSpec extends Specification{

	@Unroll
	def "Verify add #a with #b returns #expected for #p"(){
		setup:
		def ecc = new EccLib(p, 64)
		expect:
		ecc.add(a,b) == expected
		where:
		a      | b       | expected | p
		13     | 57      | 70       | 101
		13     | 9       | 22       | 23
	}
	
	@Unroll
	def "Verify sub #a with #b returns #expected for #p"(){
		setup:
		def ecc = new EccLib(p, 64)
		expect:
		ecc.sub(a,b) == expected
		where:
		a      | b       | expected | p
		13     | 57      | 57       | 101
		13     | 9       | 4        | 23
	}
	
	@Unroll
	def "Verify multiply #a with #b returns #expected for #p"(){
		setup:
		def ecc = new EccLib(p, 128)
		expect:
		ecc.multiply(a,b) == expected
		where:
		a      | b       | expected | p
		13     | 9       | 2        | 23
		13     | 57      | 34       | 101
		123    | 456     | 4        | 2003
		123    | 456     | 33       | 101
		
	}
}
