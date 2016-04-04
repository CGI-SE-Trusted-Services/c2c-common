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

import org.certificateservices.custom.c2x.common.EncodeHelper;
import org.certificateservices.custom.c2x.common.Encodable;
import org.certificateservices.custom.c2x.its.datastructs.basic.IntX;
import org.certificateservices.custom.c2x.its.datastructs.basic.Signature;

/**
 *This structure defines how to encode a generic secured message:
 *
 * <li> protocol_version specifies the applied protocol version. 
 * <li> security_profile specifies the security profile for this secured message. The profiles define the contents
 * of the variable header, payload and trailer fields. A message that does not conform to the profile is invalid. The
 * default value shall be set to 0, if no specific profile is used. Not used for version 2 messages.
 * 
 * <li> header_fields is a variable-length vector that contains multiple information fields of interest to the
 * security layer. If not defined otherwise in a message profile, the sequence of header fields shall be encoded in
 * ascending numerical order of their type value.
 * <li> payload_fields is a variable-length vector containing the message's payload. Multiple payload types in
 * one message are allowed in version 1 but not in version 2.
 * <li> trailer_fields is a variable-length vector containing information after the payload, for example,
 * necessary to verify the message's authenticity and integrity. If not defined otherwise in a message profile, the
 * sequence of trailer fields shall be encoded in ascending numerical order of the type value.
 * <p>
 * Further information about how to fill these variable-length vectors is given via security profiles in clause 7.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class SecuredMessage implements Encodable{
	
	public static final int DEFAULT_SECURITY_PROFILE = 0;
	
	public static final int DEFAULT_PROTOCOL = 2;
	
	public static final int PROTOCOL_VERSION_1 = 1;
	public static final int PROTOCOL_VERSION_2 = 2;
	
    private int protocolVersion = DEFAULT_PROTOCOL;	
    
    
	private Integer securityProfile = null;
	private List<HeaderField> headerFields;
	private List<Payload> payloadFields;
	private List<TrailerField> trailerFields;

		
	/**
	 * Main constructor for version 1 type of a SecuredMessage using the default protocol and security profile before signing, i.e no trailer fields
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
		this.protocolVersion = 1;
		this.securityProfile = securityProfile;
		this.headerFields = headerFields;
		this.payloadFields = payloadFields;
		this.trailerFields = new ArrayList<TrailerField>();
	}
	
	/**
	 * Main constructor for version 2 type of a SecuredMessage using the default protocol and security profile before signing, i.e no trailer fields
	 * are necessary.
	 * 
	 * @param securityProfile the security profile used for the message.
	 * @param headerFields is a variable-length vector that contains multiple information fields of interest to the
     * security layer. If not defined otherwise in a message profile, the sequence of header fields shall be encoded in
     * ascending numerical order of their type value. 
     * @param payloadField the message payload.   
     * @throws IllegalArgumentException if invalid parameters was given for the specific protocol version. 
	 */
	public SecuredMessage(List<HeaderField> headerFields, Payload payloadField) throws IllegalArgumentException{
		this.protocolVersion = 2;
		this.headerFields = headerFields;
		if(payloadField == null){
			throw new IllegalArgumentException("Error payload field cannot be null");
		}
		this.payloadFields = new ArrayList<Payload>(1);
		this.payloadFields.add(payloadField);
		this.trailerFields = new ArrayList<TrailerField>();
	}
	
   /**
	* Main constructor of a SecuredMessage using the default protocol and security profile.
	*
	* @param protocolVersion the protocol version used for the message.
	* @param securityProfile the security profile used for the message. Null for version 2 messages
	* @param headerFields is a variable-length vector that contains multiple information fields of interest to the
    * security layer. If not defined otherwise in a message profile, the sequence of header fields shall be encoded in
    * ascending numerical order of their type value. 
    * @param payloadFields is a variable-length vector containing the message's payload. Multiple payload types in
    * one message are allowed.
    * @param trailerFields is a variable-length vector containing information after the payload, for example,
    * necessary to verify the message's authenticity and integrity. If not defined otherwise in a message profile, the
    * sequence of trailer fields shall be encoded in ascending numerical order of the type value.   
    * @throws IllegalArgumentException if invalid parameters was given for the specific protocol version.
	 */
	public SecuredMessage(int protocolVersion, Integer securityProfile, List<HeaderField> headerFields, List<Payload> payloadFields, List<TrailerField> trailerFields) throws IllegalArgumentException{
		if(protocolVersion > 1){
			if(payloadFields.size() != 1){
				throw new IllegalArgumentException("Error Version 2 secure message must only have one payload");
			}
			if(securityProfile != null){
				throw new IllegalArgumentException("Error Version 2 secure message doesn't support security profile, must be null.");
			}
				
		}
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
		decode(dis);
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
	 * @return  the security profile used for the message. Null of protocols over 1.
	 */
	public Integer getSecurityProfile() {
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
	 * Method to fetch the version 2 payload.
	 * 
	 * @return  the message payload.
	 */
	public Payload getPayload() {
		return payloadFields.get(0);
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
	public void encode(DataOutputStream out) throws IOException {
		out.write(protocolVersion);
		if(protocolVersion == 1){
		  out.write(securityProfile);
		}
		EncodeHelper.encodeVariableSizeVector(out, headerFields);
		if(protocolVersion == 1){
		  EncodeHelper.encodeVariableSizeVector(out, payloadFields);
		}else{
		  payloadFields.get(0).encode(out);
		}
		if(trailerFields != null && trailerFields.size() > 0){
		  EncodeHelper.encodeVariableSizeVector(out, trailerFields);
		}
	}

	@SuppressWarnings("unchecked")
	@Override
	public void decode(DataInputStream in) throws IOException {	
		protocolVersion = in.read();
		if(protocolVersion == 1){
		  securityProfile = in.read();
		}
		headerFields = decodeHeaderField(in);
		if(protocolVersion == 1){
		  payloadFields = (List<Payload>) EncodeHelper.decodeVariableSizeVector(in, Payload.class);
		}else{
			Payload payloadField = new Payload();
			payloadField.decode(in);
			this.payloadFields = new ArrayList<Payload>(1);
			this.payloadFields.add(payloadField);
		}
		if(in.available() > 0){
		  trailerFields = (List<TrailerField>) EncodeHelper.decodeVariableSizeVector(in, TrailerField.class);
		}else{
		  trailerFields = new ArrayList<TrailerField>();
		}
	}

	@Override
	public String toString() {
		if(protocolVersion == 1){
		  return "SecuredMessage [protocolVersion=" + protocolVersion + ", securityProfile=" + securityProfile + "\n" +
		        "  headers:" + EncodeHelper.listToString(headerFields, "HeaderField ", true, 4) + "\n" +
				"  payloads:" + EncodeHelper.listToString(payloadFields, "Payload ", true, 4)  + "\n" +
				"  trailers:" + EncodeHelper.listToString(trailerFields, "TrailerField ", true, 4) + "\n" +
				"]";
		}
		return "SecuredMessage [protocolVersion=" + protocolVersion + "\n" +
				"  headers:" + EncodeHelper.listToString(headerFields, "HeaderField ", true, 4) + "\n" +
			    "  payload:\n" +
				"    " + getPayload().toString().replace("Payload ", "") + "\n" +
				"  trailers:" + EncodeHelper.listToString(trailerFields, "TrailerField ", true, 4) + "\n" +
				"]";
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
		encode(dos);
		return baos.toByteArray();		
	}
	
	/**
	 * Help method that serializes variable sized vector to the supplied data output stream.
	 * 
	 * @param in the data input stream to decode the variable sized vector from.
	 * 
	 * @param c class of the objects contained in data stream, the class must implement a StructSerializer
	 * @throws IOException if serialization failed.
	 */
	private  List<HeaderField> decodeHeaderField(DataInputStream in) throws IOException{
		ArrayList<HeaderField> retval = new ArrayList<HeaderField>();
    
		IntX size = new IntX();
		size.decode(in);
		byte[] data = new byte[size.getValue().intValue()];
		in.read(data);
		DataInputStream dis = new DataInputStream(new ByteArrayInputStream(data));
		while(dis.available() > 0){
			HeaderField ss = new HeaderField(protocolVersion);
			ss.decode(dis);
			retval.add(ss);    		
		}

    	
    	return retval;
	}
}
