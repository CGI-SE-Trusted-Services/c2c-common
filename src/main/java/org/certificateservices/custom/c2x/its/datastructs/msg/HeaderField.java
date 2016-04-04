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
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

import org.certificateservices.custom.c2x.common.Encodable;
import org.certificateservices.custom.c2x.common.EncodeHelper;
import org.certificateservices.custom.c2x.its.datastructs.basic.EncryptionParameters;
import org.certificateservices.custom.c2x.its.datastructs.basic.HashedId3;
import org.certificateservices.custom.c2x.its.datastructs.basic.IntX;
import org.certificateservices.custom.c2x.its.datastructs.basic.SignerInfo;
import org.certificateservices.custom.c2x.its.datastructs.basic.ThreeDLocation;
import org.certificateservices.custom.c2x.its.datastructs.basic.Time32;
import org.certificateservices.custom.c2x.its.datastructs.basic.Time64;
import org.certificateservices.custom.c2x.its.datastructs.basic.Time64WithStandardDeviation;

/**
 * This structure defines how to encode information of interest to the security layer. Its content depends on the 
 * value of type:
 * <li> generation_time: the point in time this message was generated contained in a Time64 structure shall be
 * given.
 * <li> generation_time_confidence: the point in time this message was generated with
 * additional confidence described by the standard deviation of the time value contained in a
 * Time64WithStandardDeviation structure shall be given.
 * <li> expiration: the point in time the validity of this message expires contained in a Time32 structure shall be 
 * given.
 * <li> generation_location: the location where this message was created contained in a ThreeDLocation
 * structure shall be given.
 * <li> request_unrecognized_certificate: a request for certificates shall be given in case that a
 * certificate from a peer has not been transmitted before. This request consists of a variable-length vector of
 * 3 octet long certificate digests contained in a HashedId3 structure to identify the requested certificates.
 * <li>message_type: the type of the message shall be given. These types are specified in the security profiles in
 * clause 7. Unsupported in Version 2 of the protocol
 * * <li>its_aid: The ITS-AID of the application payload shall be given. The valid ITS-AIDs are specified
 * according to ETSI TS 102 965 [7].Unsupported in Version 1 of the protocol
 *  
 * Furthermore, the HeaderField structure defines cryptographic information that is required for single-pass processing of
 * the payload:
 * <li> signer_info: information about the message's signer contained in a SignerInfo structure shall be
 * given. If present, the SignerInfo structure shall come first in the array of HeaderFields, unless this is explicitly
 * overridden by the security profile.
 * <li> encryption_parameters: additional parameters necessary for encryption purposes contained in an
 * EncryptionParameters structure shall be given.
 * <li> recipient_info: information specific for certain recipients (e.g. data encrypted with a recipients public
 * key) contained in a variable-length vector of type RecipientInfo shall be given.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class HeaderField implements Encodable{
	
	private int protocolVersion;
	
    private HeaderFieldType headerFieldType;	
	private Time64 generationTime;
	private Time64WithStandardDeviation generationTimeWithSdtDeviation;
	private Time32 expireTime;
	private ThreeDLocation generationLocation;
	private List<Encodable> relatedData;
	private int messageType;
	private SignerInfo signer;
	private EncryptionParameters encParams;
	private IntX itsAid;
	
	
	/**
	 * Main constructor of a HeaderField of type: generation_time
	 * 
	 * @param protocolVersion the version of the related secure message protocol.
	 * @param generationTime the point in time this message was generated contained in a Time64 structure
	 */
	public HeaderField(int protocolVersion, Time64 generationTime){
		this.protocolVersion = protocolVersion;
		this.headerFieldType = HeaderFieldType.generation_time;
		this.generationTime = generationTime;		
	}
	
	/**
	 * Main constructor of a HeaderField of type: generation_time_confidence
	 * 
	 * @param protocolVersion the version of the related secure message protocol.
	 * @param generationTimeWithSdtDeviation the point in time this message was generated with
     * additional confidence described by the standard deviation of the time value contained in a
     * Time64WithStandardDeviation structure
	 */
	public HeaderField(int protocolVersion,Time64WithStandardDeviation generationTimeWithSdtDeviation){
		this.protocolVersion = protocolVersion;
		this.headerFieldType = HeaderFieldType.generation_time_confidence;
		this.generationTimeWithSdtDeviation = generationTimeWithSdtDeviation;		
	}
	
	/**
	 * Main constructor of a HeaderField of type: expiration
	 * 
	 * @param protocolVersion the version of the related secure message protocol.
	 * @param expireTime the point in time the validity of this message expires contained in a Time32 structure
	 */
	public HeaderField(int protocolVersion,Time32 expireTime){
		this.protocolVersion = protocolVersion;
		this.headerFieldType = HeaderFieldType.expiration;
		this.expireTime = expireTime;		
	}
	
	/**
	 * Main constructor of a HeaderField of type: generation_location
	 * 
	 * @param protocolVersion the version of the related secure message protocol.
	 * @param generationLocation  the location where this message was created contained in a ThreeDLocation
     * structure
	 */
	public HeaderField(int protocolVersion,ThreeDLocation generationLocation){
		this.protocolVersion = protocolVersion;
		this.headerFieldType = HeaderFieldType.generation_location;
		this.generationLocation = generationLocation;		
	}
	
	/**
	 * Main constructor of a HeaderField of type: request_unrecognized_certificate or recipient_info
	 * 
	 * @param protocolVersion the version of the related secure message protocol.
	 * @param headerFieldType of either request_unrecognized_certificate or recipient_info
	 * @param relatedData specific for the given type, the type of data should be for:
	 * <li>request_unrecognized_certificate : HashId3
	 * <li>recipient_info : RecipientInfo
	 */
	public HeaderField(int protocolVersion,HeaderFieldType headerFieldType, List<Encodable> relatedData){
		this.protocolVersion = protocolVersion;
		if(headerFieldType != HeaderFieldType.request_unrecognized_certificate &&
			headerFieldType != HeaderFieldType.recipient_info){
			throw new IllegalArgumentException("Error in header field, unsupported type " + headerFieldType + " for variable sized vector.");
		}
		this.headerFieldType = headerFieldType;
		this.relatedData = relatedData;		
	}
	
	/**
	 * Main constructor of a HeaderField of type: message_type
	 * 
	 * @param protocolVersion the version of the related secure message protocol.
	 * @param messageType the type of the message shall be given. These types are specified in the security profiles in
     * clause 7.
	 */
	public HeaderField(int protocolVersion, int messageType) throws IllegalArgumentException{
		if(protocolVersion != 1){
			throw new IllegalArgumentException("Error message type header field is only supported by protocol version 1");
		}
		this.protocolVersion = protocolVersion;
		this.headerFieldType = HeaderFieldType.message_type;
		this.messageType = messageType;		
	}
	
	/**
	 * Main constructor of a HeaderField of type: its_aid
	 * 
	 * @param protocolVersion the version of the related secure message protocol.
	 * @param itsAid the ITS-AID of the application payload shall be given. The valid ITS-AIDs are specified
	 * according to ETSI TS 102 965 [7]. 
	 */
	public HeaderField(int protocolVersion, IntX itsAid) throws IllegalArgumentException{
		if(protocolVersion == 1){
			throw new IllegalArgumentException("Error message type header field is only supported by protocol version 2 and up");
		}
		this.protocolVersion = protocolVersion;
		this.headerFieldType = HeaderFieldType.its_aid;
		this.itsAid = itsAid;		
	}
	
	/**
	 * Main constructor of a HeaderField of type: signer_info
	 * 
	 * @param protocolVersion the version of the related secure message protocol.
	 * @param signer information about the message's signer contained in a SignerInfo structure shall be
     * given. If present, the SignerInfo structure shall come first in the array of HeaderFields, unless this is explicitly
     * overridden by the security profile.
	 */
	public HeaderField(int protocolVersion, SignerInfo signer){
		this.protocolVersion = protocolVersion;
		this.headerFieldType = HeaderFieldType.signer_info;
		this.signer = signer;		
	}
	
	/**
	 * Main constructor of a HeaderField of type: encryption_parameters
	 * 
	 * @param protocolVersion the version of the related secure message protocol.
	 * @param  encParams additional parameters necessary for encryption purposes contained in an
     * EncryptionParameters structure shall be given.
	 */
	public HeaderField(int protocolVersion, EncryptionParameters encParams){
		this.protocolVersion = protocolVersion;
		this.headerFieldType = HeaderFieldType.encryption_parameters;
		this.encParams = encParams;		
	}

	/**
	 * Constructor used during serializing.
	 * 
	 * @param protocolVersion the version of the related secure message protocol.
	 */
	public HeaderField(int protocolVersion){
		this.protocolVersion = protocolVersion;
	}
	
	/** 
	 * @return the type of header field, one of getHeaderFieldType enum values
	 */
	public HeaderFieldType getHeaderFieldType(){
		return headerFieldType;
	}
	
	/**
	 * 
	 * @return  the point in time this message was generated contained in a Time64 structure. 
	 * Returns null if headerFieldType isn't generation_time
	 */
	public Time64 getGenerationTime() {
		return generationTime;
	}

	/**
	 * 
	 * @return the point in time this message was generated with
     * additional confidence described by the standard deviation of the time value contained in a
     * Time64WithStandardDeviation structure. Returns null if headerFieldType isn't generation_time_confidence
	 */
	public Time64WithStandardDeviation getGenerationTimeWithSdtDeviation() {
		return generationTimeWithSdtDeviation;
	}

	/**
	 * 
	 * @return the point in time the validity of this message expires contained in a Time32 structure. Returns null 
	 * if headerFieldType isn't expiration.
	 */
	public Time32 getExpireTime() {
		return expireTime;
	}

	/**
	 * 
	 * @return  the location where this message was created contained in a ThreeDLocation
	 * structure shall be given. Returns null if headerFieldType isn't generation_location.
	 */
	public ThreeDLocation getGenerationLocation() {
		return generationLocation;
	}

	/**
	 * 
	 * @return a request for certificates shall be given in case that a
	 * certificate from a peer has not been transmitted before. This request consists of a variable-length vector of
	 * 3 octet long certificate digests contained in a HashedId3 structure to identify the requested certificates.
	 * Returns null if headerFieldType isn't request_unrecognized_certificate.
	 */
	public List<Encodable> getDigests() {
		if(headerFieldType != HeaderFieldType.request_unrecognized_certificate){
			return null;
		}
		return relatedData;
	}
	
	/**
	 *  
	 * @return information specific for certain recipients (e.g. data encrypted with a recipients public
	 * key) contained in a variable-length vector of type RecipientInfo shall be given. Returns null if 
	 * headerFieldType isn't recipient_info
	 */
	public List<Encodable> getRecipients() {
		if(headerFieldType != HeaderFieldType.recipient_info){
			return null;
		}
		return relatedData;
	}

	/**
	 * 
	 * @return the type of the message shall be given. These types are specified in the security profiles in
	 * clause 7.Returns null if headerFieldType isn't message_type
	 */
	public int getMessageType() {
		return messageType;
	}
	
	/**
	 * @return the ITS-AID of the application payload.
	 */
	public IntX getItsAid(){
		return itsAid;
	}

	/**
	 * 
	 * @return additional parameters necessary for encryption purposes contained in an
	 * EncryptionParameters structure shall be given. Returns null if 
	 * headerFieldType isn't encryption_parameters
	 */
	public EncryptionParameters getEncParams() {
		return encParams;
	}

	/**
	 * 
	 * @return information about the message's signer contained in a SignerInfo structure shall be
	 * given. If present, the SignerInfo structure shall come first in the array of HeaderFields, unless this is explicitly
	 * overridden by the security profile. Returns null if 
	 * headerFieldType isn't signer_info
	 */
	public SignerInfo getSigner() {
		return signer;
	}
	

	@Override
	public void encode(DataOutputStream out) throws IOException {
		out.write(headerFieldType.getByteValue(protocolVersion));
		switch(headerFieldType){
		case generation_time:
			generationTime.encode(out);
			break;
		case generation_time_confidence:
			generationTimeWithSdtDeviation.encode(out);
			break;
		case expiration:
			expireTime.encode(out);
			break;
		case generation_location:
			generationLocation.encode(out);
			break;
		case request_unrecognized_certificate:
		case recipient_info:
			EncodeHelper.encodeVariableSizeVector(out, relatedData);
			break;
		case message_type:
			out.write(ByteBuffer.allocate(4).putInt(messageType).array(),2,2);
			break;
		case its_aid:
			itsAid.encode(out);
			break;
		case signer_info: 
			signer.encode(out);
			break;
		case encryption_parameters:
			encParams.encode(out);
			break;

		}

	}

	@SuppressWarnings("unchecked")
	@Override
	public void decode(DataInputStream in) throws IOException {
		headerFieldType = HeaderFieldType.getByValue(protocolVersion, in.read());
		switch(headerFieldType){
		case generation_time:
			generationTime = new Time64();
			generationTime.decode(in);
			break;
		case generation_time_confidence:
			generationTimeWithSdtDeviation = new Time64WithStandardDeviation();
			generationTimeWithSdtDeviation.decode(in);
			break;
		case expiration:
			expireTime = new Time32();
			expireTime.decode(in);
			break;
		case generation_location:
			generationLocation = new ThreeDLocation();
			generationLocation.decode(in);
			break;
		case request_unrecognized_certificate:
			relatedData = (List<Encodable>) EncodeHelper.decodeVariableSizeVector(in, HashedId3.class);
			break;
		case recipient_info:
			relatedData = decodeRecipientInfo(in);
			break;
		case message_type:
			byte[] data = new byte[4];
			in.read(data,2,2);
			messageType = ByteBuffer.wrap(data).getInt();
			break;
		case its_aid:
			itsAid = new IntX();
			itsAid.decode(in);
			break;
		case signer_info: 
			signer = new SignerInfo();
			signer.decode(in);
			break;
		case encryption_parameters:
			encParams = new EncryptionParameters();
			encParams.decode(in);
			break;

		}		
	}

	@Override
	public String toString() {
		switch(headerFieldType){
		case generation_time:
			return "HeaderField [type=" + headerFieldType
					+ ", generationTime=" + generationTime.toString(protocolVersion).replace("Time64 ", "") + "]";
		case generation_time_confidence:
			return "HeaderField [type=" + headerFieldType
					+ ", generationTimeWithSdtDeviation="
					+ generationTimeWithSdtDeviation.toString(protocolVersion).replace("Time64WithStandardDeviation ", "") + "]";
		case expiration:
			return "HeaderField [type=" + headerFieldType
                    + ", expireTime=" + expireTime.toString(protocolVersion).replace("Time32 ", "")  + "]";
		case generation_location:
			return "HeaderField [type=" + headerFieldType
					+ ", generationLocation=" + generationLocation  + "]";
		case request_unrecognized_certificate:

			return "HeaderField [type=" + headerFieldType
	                + ", digests=" + EncodeHelper.listToString(getDigests(), "HashedId3 ") + "]";
		case recipient_info:
			return "HeaderField [type=" + headerFieldType					
					+ ", recipients=" + EncodeHelper.listToString(getRecipients(), "RecipientInfo ")   + "]";
		case message_type:
			return "HeaderField [type=" + headerFieldType
					+ ", messageType=" +messageType + "]";
		case its_aid:
			return "HeaderField [type=" + headerFieldType
					+ ", value=" +itsAid.toString().replaceAll("IntX ", "") + "]";
		case signer_info: 
			return "HeaderField [type=" + headerFieldType
					+ ", signer=" + signer.toString().replace("SignerInfo ", "") + "]";
		case encryption_parameters:
			return "HeaderField [type=" + headerFieldType
                    + ", encParams="
					+ encParams.toString().replace("EncryptionParameters ", "") + "]";
		default:
			return "HeaderField [unknown]";
		}
		
	}
	
	/**
	 * Help method that serializes variable sized vector to the supplied data output stream.
	 * 
	 * @param in the data input stream to decode the variable sized vector from.
	 * 
	 * @param c class of the objects contained in data stream, the class must implement a StructSerializer
	 * @throws IOException if serialization failed.
	 */
	private  List<Encodable> decodeRecipientInfo(DataInputStream in) throws IOException{
		ArrayList<Encodable> retval = new ArrayList<Encodable>();
    
		IntX size = new IntX();
		size.decode(in);
		byte[] data = new byte[size.getValue().intValue()];
		in.read(data);
		DataInputStream dis = new DataInputStream(new ByteArrayInputStream(data));
		while(dis.available() > 0){
			Encodable ss = new RecipientInfo(protocolVersion);
			ss.decode(dis);
			retval.add(ss);    		
		}

    	
    	return retval;
	}
}
