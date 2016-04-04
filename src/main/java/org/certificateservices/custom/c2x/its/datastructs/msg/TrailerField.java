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

import org.certificateservices.custom.c2x.common.Encodable;
import org.certificateservices.custom.c2x.its.datastructs.basic.Signature;

/**
 * This structure defines how to encode information used by the security layer after processing the payload. A trailer field 
 * may contain data of the following cases:
 *
 * <li> signature: the signature of this message contained in a Signature structure shall be given. The 
 * signature is calculated over the hash of the encoding of all previous fields (version, header_fields
 * field and the payload_fields field), including the encoding of their length.
 * If there is a payload field with type equal to signed_external, the data shall be included in the hash
 * calculation immediately after the payload field, encoded as an opaque<var>, i.e. as if it was included.
 * If there is one or more payload field whose type does not contain the keyword "signed" (unsecured or
 * encrypted), the length fields shall be included, the corresponding data fields shall be excluded from the
 * hash calculation.
 * 
 * If further trailer fields are included in a SecuredMessage, the signature structure shall include all fields
 * in the sequence before, and exclude all fields in the sequence after the signature structure, if not otherwise
 * defined via security profiles.
 * 
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class TrailerField implements Encodable{
	
    private TrailerFieldType trailerFieldType;	
	private Signature signature;
	
	/**
	 * Main constructor of a TrailerField containing a signature
	 * 
	 * @param signature the signature of this message contained in a Signature structure
	 */
	public TrailerField(Signature signature){
		this.trailerFieldType = TrailerFieldType.signature;
		this.signature = signature;		
	}
	
	/**
	 * Constructor used during serializing.
	 * 
	 */
	public TrailerField(){
	}
	
	/** 
	 * @return the type of trailer field, one of TrailerFieldType enum values
	 */
	public TrailerFieldType getTrailerFieldType(){
		return trailerFieldType;
	}
	
	/** 
	 * @return the signature of this message contained.
	 */
	public Signature getSignature(){
		return signature;
	}
	

	@Override
	public void encode(DataOutputStream out) throws IOException {
		out.write(trailerFieldType.getByteValue());
		switch(trailerFieldType){
		case signature:
			signature.encode(out);	
			break;
		default:
			break;
		}
		
	}

	@Override
	public void decode(DataInputStream in) throws IOException {
		trailerFieldType = TrailerFieldType.getByValue(in.read());
		switch(trailerFieldType){
		case signature:
			signature = new Signature();
			signature.decode(in);	
			break;
		default:
			break;
		}
			
	}

	@Override
	public String toString() {
		return "TrailerField [trailerFieldType=" + trailerFieldType
				+ ", signature=" + signature.toString().replace("Signature ", "") + "]";
	}
	

}
