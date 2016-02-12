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

import org.certificateservices.custom.c2x.common.Encodable;

import static org.certificateservices.custom.c2x.its.datastructs.basic.PublicKeyAlgorithm.*;

/**
 * This structure defines a container that encapsulates signatures based on public key cryptography. Depending on the
 * value of algorithm, different data structures define the algorithm-specific details:
 *<p>
 * The following algorithms are supportd
 * <li>ecdsa_nistp256_with_sha256 
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class Signature implements Encodable{
	
	private PublicKeyAlgorithm publicKeyAlgorithm;
	private EcdsaSignature ecdsaSignature;
	
	/**
	 * Main constructor for a related EcdsaSignature
	 * 
	 * @param publicKeyAlgorithm the related public key algorithm
	 * @param ecdsaSignature the related EcdsaSignature
	 * @throws if given public key algorithm was unsupported.
	 */
	public Signature(PublicKeyAlgorithm publicKeyAlgorithm, EcdsaSignature ecdsaSignature) throws IllegalArgumentException{
		if(publicKeyAlgorithm != ecdsa_nistp256_with_sha256){
			throw new IllegalArgumentException("Error unsupported public key algorithm: " + publicKeyAlgorithm);
		}
		this.publicKeyAlgorithm = publicKeyAlgorithm;
		this.ecdsaSignature = ecdsaSignature;		
	}
	

	
	/**
	 * Constructor used during serializing.
	 * 
	 */
	public Signature(){
	}
	
	/** 
	 * @return the related public key algorithm.
	 */
	public PublicKeyAlgorithm getPublicKeyAlgorithm(){
		return publicKeyAlgorithm;
	}
	
	/** 
	 * @return the related ecdsa signature value or null if no related ecdsa signature exists.
	 */
	public EcdsaSignature getSignatureValue(){
		return ecdsaSignature;
	}


	@Override
	public void encode(DataOutputStream out) throws IOException {
		out.write(publicKeyAlgorithm.getByteValue());
		if(publicKeyAlgorithm == ecdsa_nistp256_with_sha256){
		   ecdsaSignature.encode(out);	
		}		
	}

	@Override
	public void decode(DataInputStream in) throws IOException {
		publicKeyAlgorithm = PublicKeyAlgorithm.getByValue(in.read());
		if(publicKeyAlgorithm == ecdsa_nistp256_with_sha256){
			ecdsaSignature = new EcdsaSignature(publicKeyAlgorithm);
			ecdsaSignature.decode(in);
		}
	}

	@Override
	public String toString() {
		return "Signature [publicKeyAlgorithm=" + publicKeyAlgorithm
				+ ", ecdsaSignature=" + ecdsaSignature + "]";
	}
	

}
