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

import static org.certificateservices.custom.c2x.its.datastructs.basic.PublicKeyAlgorithm.ecies_nistp256;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;

import org.certificateservices.custom.c2x.common.Encodable;

/**
 * <code>
 * struct {
 *  PublicKeyAlgorithm algorithm;
 *  select(algorithm) {
 *  case ecdsa_nistp256_with_sha256:
 *    EccPoint public_key;
 *  case ecies_nistp256:
 *    SymmetricAlgorithm supported_symm_alg;
 *    EccPoint public_key;
 * } PublicKey;
 * </code>
 * 
 * This structure defines a wrapper for public keys by specifying the used algorithm and - depending on the value of
 * algorithm - the necessary data fields:
 * <li>ecdsa_nistp256_with_sha256: the specific details regarding ECC contained in an EccPoint structure shall be given.
 * <li>ecies_nistp256: the specific details regarding ECC contained in an EccPoint structure and the
 * symmetric key algorithm contained in a SymmetricAlgorithm structure shall be given.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class PublicKey implements Encodable{
	
	private PublicKeyAlgorithm publicKeyAlgorithm;
	private EccPoint publicKey;
    private SymmetricAlgorithm supportedSymmAlg;
	
	/**
	 * Main constructor for Public Keys of type ecdsa_nistp256_with_sha256
	 * 
	 * @param publicKeyAlgorithm the related public key algorithm
	 * @param publicKey the public key
	 */
	public PublicKey(PublicKeyAlgorithm publicKeyAlgorithm, EccPoint publicKey){
		this(publicKeyAlgorithm, publicKey, null);
	}
	
	/**
	 * Main constructor for Public Keys of type ecies_nistp256
	 * 
	 * @param publicKeyAlgorithm the related public key algorithm
	 * @param publicKey the public key
	 * @param supportedSymmAlg the related supported symmetric algorithm.
	 */
	public PublicKey(PublicKeyAlgorithm publicKeyAlgorithm, EccPoint publicKey, SymmetricAlgorithm supportedSymmAlg){
		this.publicKeyAlgorithm = publicKeyAlgorithm;
		this.publicKey = publicKey;
		this.supportedSymmAlg = supportedSymmAlg;
	}
	

	
	/**
	 * Constructor used during serializing.
	 * 
	 */
	public PublicKey(){
	}
	
	/** 
	 * @return the public key algorithm
	 */
	public PublicKeyAlgorithm getPublicKeyAlgorithm(){
		return publicKeyAlgorithm;
	}
	
	
	/** 
	 * @return the public key ecc point
	 */
	public EccPoint getPublicKey(){
		return publicKey;
	}
	
	/** 
	 * @return the supported symmetric algorithm or null of not public key algorithm of ecies_nistp256.
	 */
	public SymmetricAlgorithm getSupportedSymmAlg(){
		if(publicKeyAlgorithm != ecies_nistp256){
			return null;
		}
		 return supportedSymmAlg;
	}


	@Override
	public void encode(DataOutputStream out) throws IOException {
		out.write(publicKeyAlgorithm.getByteValue());
		if(publicKeyAlgorithm == ecies_nistp256){
			out.writeByte(supportedSymmAlg.getByteValue());
		}
		publicKey.encode(out);
	}

	@Override
	public void decode(DataInputStream in) throws IOException {
		publicKeyAlgorithm = PublicKeyAlgorithm.getByValue(in.read());
		if(publicKeyAlgorithm == ecies_nistp256){
			supportedSymmAlg = SymmetricAlgorithm.getByValue(in.readByte());
		}
		publicKey = new EccPoint(publicKeyAlgorithm);
		publicKey.decode(in);
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result
				+ ((publicKey == null) ? 0 : publicKey.hashCode());
		result = prime
				* result
				+ ((publicKeyAlgorithm == null) ? 0 : publicKeyAlgorithm
						.hashCode());
		result = prime
				* result
				+ ((supportedSymmAlg == null) ? 0 : supportedSymmAlg.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		PublicKey other = (PublicKey) obj;
		if (publicKey == null) {
			if (other.publicKey != null)
				return false;
		} else if (!publicKey.equals(other.publicKey))
			return false;
		if (publicKeyAlgorithm != other.publicKeyAlgorithm)
			return false;
		if (supportedSymmAlg != other.supportedSymmAlg)
			return false;
		return true;
	}

	@Override
	public String toString() {
		return "PublicKey [publicKeyAlgorithm=" + publicKeyAlgorithm
				+ ", publicKey=" + publicKey.toString().replaceAll("EccPoint ", "") + ", supportedSymmAlg="
				+ supportedSymmAlg + "]";
	}


}
