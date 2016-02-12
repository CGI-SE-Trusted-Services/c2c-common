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

import static org.certificateservices.custom.c2x.its.datastructs.basic.SymmetricAlgorithm.*;

/**
 * This structure holds basic parameters and additional data required for encryption and decryption of data using different
 * symmetric encryption algorithms. In case of aes_128_ccm a 12 octet nonce shall be given. In other cases the data
 * shall be given as a variable-length vector containing opaque data. It is out of scope of this definition how resulting
 * ciphertexts are transported. Typically, a ciphertext should be put into a Payload data structure marked as
 * encrypted using the PayloadType.
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class EncryptionParameters implements Encodable{
	
	private SymmetricAlgorithm symmetricAlgorithm;
	private byte[] nonce;
	
	/**
	 * Default constructor
	 * @param symmetricAlgorithm the SymmetricAlgorithm to use
	 * @param nounce a 12 byte nounce value.
	 * @throws if unsupported symmetricAlgorithm is specified.
	 */
	public EncryptionParameters(SymmetricAlgorithm symmetricAlgorithm, byte[] nounce) throws IllegalArgumentException{
		if(symmetricAlgorithm != aes_128_ccm){
			throw new IllegalArgumentException("Error: unsupported symmetric algorithm " + symmetricAlgorithm);
		}
		if(nounce == null || nounce.length != 12){
			throw new IllegalArgumentException("Error: illegal nounce, should be 12 bytes");
		}
		
		this.symmetricAlgorithm = symmetricAlgorithm;
		this.nonce = nounce;
	}
	
	/**
	 * Constructor used for serialization
	 */
	public EncryptionParameters(){}
	
	public SymmetricAlgorithm getSymmetricAlgorithm(){
		return symmetricAlgorithm;
	}

	public byte[] getNounce(){
		return nonce;
	}

	@Override
	public void encode(DataOutputStream out) throws IOException {
		out.write(symmetricAlgorithm.getByteValue());
		out.write(nonce);
	}

	@Override
	public void decode(DataInputStream in) throws IOException {
		symmetricAlgorithm = SymmetricAlgorithm.getByValue(in.read());
		if(symmetricAlgorithm != aes_128_ccm){
			throw new IOException("Error: unsupported symmetric algorithm " + symmetricAlgorithm);
		}
		this.nonce = new byte[12];
		in.read(nonce);
	}

	@Override
	public String toString() {
		return "EncryptionParameters [symmetricAlgorithm=" + symmetricAlgorithm
				+ ", nonce=" + Arrays.toString(nonce) + "]";
	}

}
