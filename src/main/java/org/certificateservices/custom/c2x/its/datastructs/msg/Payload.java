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

import org.certificateservices.custom.c2x.common.Encodable;
import org.certificateservices.custom.c2x.its.datastructs.basic.IntX;

/**
 * This structure defines how to encode payload. In case of externally signed payload, no payload data shall be given as all
 * data is external. In this case, the signature shall be contained in the trailer fields. In all other cases, the data shall be
 * given as a variable-length vector containing opaque data.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class Payload implements Encodable{
	
	
	private PayloadType payloadType;
	private byte[] data;
	

	/**
	 * Main constructor of all payload types except signed_external
	 * 
	 * @param payloadType the type of payload, one of PayloadType values
	 * @param data the payload data.
	 */
	public Payload(PayloadType payloadType, byte[] data){
		if(payloadType != PayloadType.signed_external && data == null){
			throw new IllegalArgumentException("Error payload data cannot be null for type: " + payloadType);
		}
		this.payloadType = payloadType;
		this.data = data;
	}
	
	/**
	 * Constructor used during serializing or type signed_external
	 * 
	 */
	public Payload(){
		this.payloadType = PayloadType.signed_external;
	}
	
	/** 
	 * @return the type of payload, one of PayloadType enums.
	 */
	public PayloadType getPayloadType(){
		return payloadType;
	}
	
	/** 
	 * @return the payload data, might be null if payload type is signer_external.
	 */
	public byte[] getData(){
		return data;
	}
	
	/** 
	 * @param data the payload data, might be null if payload type is signer_external.
	 */
	public void setData(byte[] data){
		this.data=data;
	}

	@Override
	public void encode(DataOutputStream out) throws IOException {
		out.write(payloadType.getByteValue());
		if(payloadType != PayloadType.signed_external){
		  IntX length = new IntX(data.length);
		  length.encode(out);
		  out.write(data);
		}
	}

	@Override
	public void decode(DataInputStream in) throws IOException {
		payloadType = PayloadType.getByValue(in.read());
		if(payloadType != PayloadType.signed_external){
			IntX length = new IntX();
			length.decode(in);
			data = new byte[length.getValue().intValue()];
			in.read(data);
		}
			
	}

	@Override
	public String toString() {
		if(payloadType == PayloadType.signed_external){
			return "Payload [payloadType=" + payloadType  + "]";
		}
		return "Payload [payloadType=" + payloadType + ", data="
				+ Arrays.toString(data) + "]";
	}

	

}
