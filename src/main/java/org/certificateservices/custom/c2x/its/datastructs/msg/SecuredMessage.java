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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.certificateservices.custom.c2x.its.datastructs.SerializationHelper;
import org.certificateservices.custom.c2x.its.datastructs.StructSerializer;
import org.certificateservices.custom.c2x.its.datastructs.basic.Signature;

/**
 *This structure defines how to encode a generic secured message:
 *
 * <li> protocol_version specifies the applied protocol version. For compliance with the present document,
 * protocol version 1 shall be used.
 * <li> security_profile specifies the security profile for this secured message. The profiles define the contents
 * of the variable header, payload and trailer fields. A message that does not conform to the profile is invalid. The
 * default value shall be set to 0, if no specific profile is used.
 * <li> header_fields is a variable-length vector that contains multiple information fields of interest to the
 * security layer. If not defined otherwise in a message profile, the sequence of header fields shall be encoded in
 * ascending numerical order of their type value.
 * <li> payload_fields is a variable-length vector containing the message's payload. Multiple payload types in
 * one message are allowed. 
 * <li> trailer_fields is a variable-length vector containing information after the payload, for example,
 * necessary to verify the message's authenticity and integrity. If not defined otherwise in a message profile, the
 * sequence of trailer fields shall be encoded in ascending numerical order of the type value.
 * <p>
 * Further information about how to fill these variable-length vectors is given via security profiles in clause 7.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class SecuredMessage implements StructSerializer{
	
	public static final int DEFAULT_PROTOCOL = 1;
	public static final int DEFAULT_SECURITY_PROFILE = 0;
	
    private int protocolVersion = DEFAULT_PROTOCOL;	
	private int securityProfile = DEFAULT_SECURITY_PROFILE;
	private List<HeaderField> headerFields;
	private List<Payload> payloadFields;
	private List<TrailerField> trailerFields;

		
	/**
	 * Main constructor of a SecuredMessage using the default protocol and security profile before signing, i.e no trailer fields
	 * are necessary.
	 * 
	 * @param securityProfile the security profile used for the message.
	 * @param headerFields is a variable-length vector that contains multiple information fields of interest to the
     * security layer. If not defined otherwise in a message profile, the sequence of header fields shall be encoded in
     * ascending numerical order of their type value. 
     * @param payloadFields is a variable-length vector containing the message's payload. Multiple payload types in
     * one message are allowed.   
	 */
	public SecuredMessage(int securityProfile, List<HeaderField> headerFields, List<Payload> payloadFields){
		this.securityProfile = securityProfile;
		this.headerFields = headerFields;
		this.payloadFields = payloadFields;
		this.trailerFields = new ArrayList<TrailerField>();
	}
	
   /**
	* Main constructor of a SecuredMessage using the default protocol and security profile.
	*
	* @param protocolVersion the protocol version used for the message.
	* @param securityProfile the security profile used for the message.
	* @param headerFields is a variable-length vector that contains multiple information fields of interest to the
    * security layer. If not defined otherwise in a message profile, the sequence of header fields shall be encoded in
    * ascending numerical order of their type value. 
    * @param payloadFields is a variable-length vector containing the message's payload. Multiple payload types in
    * one message are allowed.
    * @param trailerFields is a variable-length vector containing information after the payload, for example,
    * necessary to verify the message's authenticity and integrity. If not defined otherwise in a message profile, the
    * sequence of trailer fields shall be encoded in ascending numerical order of the type value.   
	 */
	public SecuredMessage(int protocolVersion, int securityProfile, List<HeaderField> headerFields, List<Payload> payloadFields, List<TrailerField> trailerFields){
		this.protocolVersion = protocolVersion;
		this.securityProfile = securityProfile;
		this.headerFields = headerFields;
		this.payloadFields = payloadFields;
		this.trailerFields = trailerFields;
	}


	/**
	 * Constructor creating a secured message from an encoded byte array.
	 * @param encodedMessage byte array encoding of the secured message.
	 * @throws IOException   if communication problems occurred during serialization.
	 */
	public SecuredMessage(byte[] encodedMessage) throws IOException{
		DataInputStream dis = new DataInputStream(new  ByteArrayInputStream(encodedMessage));
		deserialize(dis);
	}
	

	/**
	 * Constructor used during serializing.
	 * 
	 */
	public SecuredMessage(){
	}


	/**
	 * @return the protocol version used for the message.
	 */
	public int getProtocolVersion() {
		return protocolVersion;
	}

	/**
	 * @return  the security profile used for the message.
	 */
	public int getSecurityProfile() {
		return securityProfile;
	}

	/**
	 * @return is a variable-length vector that contains multiple information fields of interest to the
     * security layer. If not defined otherwise in a message profile, the sequence of header fields shall be encoded in
     * ascending numerical order of their type value. 
	 */
	public List<HeaderField> getHeaderFields() {
		return headerFields;
	}

	/**
	 * @return  is a variable-length vector containing the message's payload. Multiple payload types in
     * one message are allowed.
	 */
	public List<Payload> getPayloadFields() {
		return payloadFields;
	}

	/**
	 * @return is a variable-length vector containing information after the payload, for example,
     * necessary to verify the message's authenticity and integrity. If not defined otherwise in a message profile, the
     * sequence of trailer fields shall be encoded in ascending numerical order of the type value.  
	 */
	public List<TrailerField> getTrailerFields() {
		return trailerFields;
	}
	
    /**
     * Attaches a generated signature as a trailer field to the message.
     * 
     * @param signature the signature of the message to attach.
     */
	public void attachSignature(Signature signature){
		if(trailerFields == null){
			trailerFields = new ArrayList<TrailerField>();
		}
		this.trailerFields.add(new TrailerField(signature));
	}

	@Override
	public void serialize(DataOutputStream out) throws IOException {
		out.write(protocolVersion);
		out.write(securityProfile);
		
		SerializationHelper.encodeVariableSizeVector(out, headerFields);
		SerializationHelper.encodeVariableSizeVector(out, payloadFields);
		if(trailerFields != null && trailerFields.size() > 0){
		  SerializationHelper.encodeVariableSizeVector(out, trailerFields);
		}
	}

	@SuppressWarnings("unchecked")
	@Override
	public void deserialize(DataInputStream in) throws IOException {	
		protocolVersion = in.read();
		securityProfile = in.read();
		
		headerFields = (List<HeaderField>) SerializationHelper.decodeVariableSizeVector(in, HeaderField.class);
		payloadFields = (List<Payload>) SerializationHelper.decodeVariableSizeVector(in, Payload.class);
		if(in.available() > 0){
		  trailerFields = (List<TrailerField>) SerializationHelper.decodeVariableSizeVector(in, TrailerField.class);
		}else{
		  trailerFields = new ArrayList<TrailerField>();
		}
	}

	@Override
	public String toString() {
		return "SecuredMessage [protocolVersion=" + protocolVersion
				+ ", securityProfile=" + securityProfile + ", headerFields="
				+ headerFields + ", payloadFields=" + payloadFields
				+ ", trailerFields=" + trailerFields + "]";
	}

	/**
	 * Encodes the secured message as a byte array.
	 * 
	 * @return return encoded version of the secured message as a byte[] 
	 * @throws IOException if encoding problems of the secured message occurred.
	 */
	public byte[] getEncoded() throws IOException{
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		DataOutputStream dos = new DataOutputStream(baos);
		serialize(dos);
		return baos.toByteArray();		
	}
	
}
