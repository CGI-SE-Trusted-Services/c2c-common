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
package org.certificateservices.custom.c2x.its.datastructs.basic;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.Arrays;

import org.certificateservices.custom.c2x.common.Encodable;

/**
 * This structure defines the details needed to describe an ECDSA based signature. The field s contains the signature. This
 * field's length field_size is derived from the applied ECDSA algorithm.
 * 
 * R contains the associated ECC public key.
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class EcdsaSignature implements Encodable{
	
	private PublicKeyAlgorithm publicKeyAlgorithm;
	private EccPoint r;
	private byte[] signatureValue;
	
	/**
	 * Main constructor for EcdsaSignature
	 * 
	 * @param publicKeyAlgorithm the related public key algorithm
	 * @param r eccPointType representing the public key
	 * @param signatureValue the generated signature value
	 * @throws if length if signature value doesn't match the field size of the matching public key algorithm.
	 */
	public EcdsaSignature(PublicKeyAlgorithm publicKeyAlgorithm, EccPoint r, byte[] signatureValue) throws IllegalArgumentException{
		this.publicKeyAlgorithm = publicKeyAlgorithm;
		this.r = r;		
		if(publicKeyAlgorithm.getFieldSize() != signatureValue.length){
			throw new IllegalArgumentException("Error length if signature value doesn't match the the field size of the public key algorithm.");
		}
		this.signatureValue = signatureValue;
	}
	

	
	/**
	 * Constructor used during serializing.
	 * 
	 * @param publicKeyAlgorithm the related public key algorithm
	 */
	public EcdsaSignature(PublicKeyAlgorithm publicKeyAlgorithm){
		this.publicKeyAlgorithm = publicKeyAlgorithm;
	}
	
	/** 
	 * @return the related public key.
	 */
	public EccPoint getR(){
		return r;
	}
	
	/** 
	 * @return the signature value, should have the size of the related public key algorithms associated field size.
	 */
	public byte[] getSignatureValue(){
		return signatureValue;
	}


	@Override
	public void encode(DataOutputStream out) throws IOException {
		r.encode(out);
		out.write(signatureValue);		
	}

	@Override
	public void decode(DataInputStream in) throws IOException {
		r = new EccPoint(publicKeyAlgorithm);
		r.decode(in);
		signatureValue = new byte[publicKeyAlgorithm.getFieldSize()];
		in.read(signatureValue);
	}


	

	@Override
	public String toString() {
		return "EcdsaSignature [publicKeyAlgorithm=" + publicKeyAlgorithm
				+ ", r=" + r + ", signatureValue="
				+ Arrays.toString(signatureValue) + "]";
	}
	

}
