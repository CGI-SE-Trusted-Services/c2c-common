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
package org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.asn1.coer.COERChoice;
import org.certificateservices.custom.c2x.asn1.coer.COERChoiceEnumeration;
import org.certificateservices.custom.c2x.asn1.coer.COEREncodable;
import org.certificateservices.custom.c2x.asn1.coer.COEROctetStream;
import org.certificateservices.custom.c2x.common.crypto.Algorithm;
import org.certificateservices.custom.c2x.common.crypto.AlgorithmIndicator;

/**
 * This data structure encapsulates a ciphertext generated with an approved symmetric algorithm.
 * <p>
 *     <b>Critical information fields:</b>If present, this is a critical information field as defined in 5.2.5. An
 * implementation that does not recognize the indicated CHOICE value for this type in an encrypted SPDU
 * shall reject the SPDU as invalid.
 * </p>
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class SymmetricEncryptionKey extends COERChoice {
	
	private static final int OCTETSTRING_SIZE = 16;
	
	private static final long serialVersionUID = 1L;
	
	public enum SymmetricEncryptionKeyChoices implements COERChoiceEnumeration{
		aes128Ccm;

		@Override
		public COEREncodable getEmptyCOEREncodable() throws IOException {
			return new COEROctetStream(OCTETSTRING_SIZE,OCTETSTRING_SIZE);
		}

		/**
		 * @return always false, no extension exists.
		 */
		@Override
		public boolean isExtension() {
			return false;
		}

		/**
		 * Help method retrieving symmetric key from
		 * @param alg algorithm indicator to lookup SymmetricEncryptionKeyChoices from.
		 * @return related SymmetricEncryptionKeyChoices
		 * @throws IOException if invalid algorithm was found.
		 */
		public static SymmetricEncryptionKeyChoices getChoiceFromAlgorithm(AlgorithmIndicator alg) throws IOException{
			if(alg.getAlgorithm().getSymmetric() == Algorithm.Symmetric.aes128Ccm){
				return aes128Ccm;
			}
			throw new IOException("Invalid algorithm specified for SymmetricEncryptionKey: " + alg.getAlgorithm().getSymmetric());
		}
	}
	
	/**
	 * Constructor used when encoding.
	 */
	public SymmetricEncryptionKey(SymmetricEncryptionKeyChoices choice, byte[] value) throws IOException{
		super(choice, new COEROctetStream(value, OCTETSTRING_SIZE,OCTETSTRING_SIZE));
	}
	
	/**
	 * Constructor used when decoding.
	 */
	public SymmetricEncryptionKey() {
		super(SymmetricEncryptionKeyChoices.class);
	}
		
	/**
	 * Returns the type of point.
	 */
	public SymmetricEncryptionKeyChoices getType(){
		return (SymmetricEncryptionKeyChoices) choice;
	}


	/**
	 * Encodes the SymmetricEncryptionKey as a byte array.
	 *
	 * @return return encoded version of the ToBeSignedData as a byte[]
	 * @throws IOException if encoding problems of the data occurred.
	 */
	public byte[] getEncoded() throws IOException{
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		DataOutputStream dos = new DataOutputStream(baos);
		encode(dos);
		return baos.toByteArray();
	}

	@Override
	public String toString() {
		return "SymmetricEncryptionKey [" + choice + "=" +  new String(Hex.encode(((COEROctetStream) value).getData())) + "]";
	}
	
}
