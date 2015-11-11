/**
 * 
 */
package org.certificateservices.custom.c2x.ecc;

import java.math.BigInteger;
import java.security.spec.ECPoint;

/**
 * @author philip
 *
 */
public class EccLib {

	private long p;
	private int bitLength;
	
	EccLib(long p, int bitLength){
		this.p = p;
		this.bitLength = bitLength;
	}
	
	public long  getP(){
		return p;
	}
	
	public int getBitLength(){
		return bitLength;
	}
	
	public long add(long a , long b){
		return (a+b) % p;
	}
	
	public long sub(long a , long b){
		long r = (a-b);
		if(r < 0){
			return r + p;
		}
		
		return r % p;
	
	}
	
	/*
	 * def multiply(i, j):
    n = i
    r = 0
    for bit in range(bitlength):
        if (j & (1 << bit)):
            r = (r + n) % p
        n = (n + n) % p
    return r
	 */
	
	
	public long multiply2(long a, long b){
		long r = 0;
		for(int i=0; i<b;i++){
			r = add(r,a);
		}
		return r;
	}
//	public long multiply(BigInteger a, BigInteger b){
//		long n = a, r=0;
//		int bitLength = (int) Math.ceil(Math.log(p));
//		for(int bit=0;bit<bitLength;bit++){
//			if ((b & (1L << bit)) != 0){
//				r = (r+n) %p;
//			}
//			n = (n+n) %p;
//		}
//
//		return r;
//	}
	
	ECPoint asdf;
	ECPoint R = ECPoint.POINT_INFINITY;
}
