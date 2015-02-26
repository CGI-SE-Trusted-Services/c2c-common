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
package org.certificateservices.custom.c2x.its.datastructs.msg;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.Arrays;

import org.certificateservices.custom.c2x.its.datastructs.StructSerializer;
import org.certificateservices.custom.c2x.its.datastructs.basic.EccPoint;
import org.certificateservices.custom.c2x.its.datastructs.basic.PublicKeyAlgorithm;
import org.certificateservices.custom.c2x.its.datastructs.basic.SymmetricAlgorithm;

/**
 * This structure defines how to transmit an EciesNistP256-encrypted symmetric key as defined in IEEE
 * Std 1363a-2004 [i.1]. The EccPoint v contains the sender's ECC key used for the Elliptic Curve Encryption Scheme.
 * The vector c contains the encrypted public key. The vector t contains the output tag. The symm_key_len defining
 * the length of vector c containing the raw key shall be derived from the given algorithm symm_alg and the mapping as
 * defined in table 4. The necessary algorithm shall be given as an external link to the parameter symm_algorithm
 * specified in the structure EncryptionParameters. To ensure the external link to the SymmetricAlgorithm
 * symm_alg can be resolved, this EciesNistP256EncryptedKey structure shall be preceded by an according
 * EncryptionParameters structure.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class EciesNistP256EncryptedKey implements StructSerializer{
	
	public static final int OUTPUT_TAG_LENGTH = 20;
	
	private PublicKeyAlgorithm publicKeyAlgorithm;
	private EccPoint v;
	private byte[] c;
	private byte[] t;
	

	/**
	 * Main constructor of a EciesNistP256EncryptedKey
	 * 
	 * @param publicKeyAlgorithm the related public key algorithm
	 * @param v contains the sender's ECC key used for the Elliptic Curve Encryption Scheme
	 * @param c the vector c contains the encrypted public key
	 * @param t the vector t contains the output tag
	 */
	public EciesNistP256EncryptedKey(PublicKeyAlgorithm publicKeyAlgorithm, EccPoint v, byte[] c, byte[] t){
		if(t.length != OUTPUT_TAG_LENGTH){
			throw new IllegalArgumentException("Illegal argument, t value must be " + OUTPUT_TAG_LENGTH + " bytes.");
		}
		if(c.length != publicKeyAlgorithm.getRelatedSymmetricAlgorithm().getKeyLength()){
			throw new IllegalArgumentException("Illegal argument, c value length " + c.length + " doesn't match related symmetric algorithm key length " + publicKeyAlgorithm.getRelatedSymmetricAlgorithm().getKeyLength() + ".");
		}
		this.publicKeyAlgorithm = publicKeyAlgorithm;
		this.v = v;
		this.c = c;
		this.t = t;
	}
	
	/**
	 * Constructor used during serializing.
	 * 
	 * @param publicKeyAlgorithm the related public key algorithm
	 */
	public EciesNistP256EncryptedKey(PublicKeyAlgorithm publicKeyAlgorithm){
		this.publicKeyAlgorithm = publicKeyAlgorithm;
	}
	
	/** 
	 * @return the related public key algorithm.
	 */
	public PublicKeyAlgorithm getPublicKeyAlgorithm(){
		return publicKeyAlgorithm;
	}
	
	/** 
	 * @return the related symmetric algorithm.
	 */
	public SymmetricAlgorithm getSymmetricAlgorithm(){
		return publicKeyAlgorithm.getRelatedSymmetricAlgorithm();
	}
	
	/** 
	 * @return the sender's ECC key used for the Elliptic Curve Encryption Scheme.
	 */
	public EccPoint getV(){
		return v;
	}
	
	/** 
	 * @return the vector c contains the encrypted public key.
	 */
	public byte[] getC(){
		return c;
	}
	
	/** 
	 * @return the vector t contains the output tag.
	 */
	public byte[] getT(){
		return t;
	}


	@Override
	public void serialize(DataOutputStream out) throws IOException {
		v.serialize(out);
		out.write(c);
		out.write(t);
	}

	@Override
	public void deserialize(DataInputStream in) throws IOException {
		v = new EccPoint(publicKeyAlgorithm);
		v.deserialize(in);
		c = new byte[publicKeyAlgorithm.getRelatedSymmetricAlgorithm().getKeyLength()];
		in.read(c);
		t = new byte[OUTPUT_TAG_LENGTH];
		in.read(t);
			
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + Arrays.hashCode(c);
		result = prime
				* result
				+ ((publicKeyAlgorithm == null) ? 0 : publicKeyAlgorithm
						.hashCode());
		result = prime * result + Arrays.hashCode(t);
		result = prime * result + ((v == null) ? 0 : v.hashCode());
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
		EciesNistP256EncryptedKey other = (EciesNistP256EncryptedKey) obj;
		if (!Arrays.equals(c, other.c))
			return false;
		if (publicKeyAlgorithm != other.publicKeyAlgorithm)
			return false;
		if (!Arrays.equals(t, other.t))
			return false;
		if (v == null) {
			if (other.v != null)
				return false;
		} else if (!v.equals(other.v))
			return false;
		return true;
	}

	@Override
	public String toString() {
		return "EciesNistP256EncryptedKey [publicKeyAlgorithm="
				+ publicKeyAlgorithm + ", symmetricAlgorithm="
				+ publicKeyAlgorithm.getRelatedSymmetricAlgorithm() + ", v=" + v + ", c=" + Arrays.toString(c)
				+ ", t=" + Arrays.toString(t) + "]";
	}




	

}
