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
package org.certificateservices.custom.c2x.its.generator;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.certificateservices.custom.c2x.common.Encodable;
import org.certificateservices.custom.c2x.its.crypto.CryptoManager;
import org.certificateservices.custom.c2x.its.datastructs.basic.HashedId3;
import org.certificateservices.custom.c2x.its.datastructs.basic.PublicKeyAlgorithm;
import org.certificateservices.custom.c2x.its.datastructs.basic.SignerInfoType;
import org.certificateservices.custom.c2x.its.datastructs.basic.ThreeDLocation;
import org.certificateservices.custom.c2x.its.datastructs.basic.Time64;
import org.certificateservices.custom.c2x.its.datastructs.cert.Certificate;
import org.certificateservices.custom.c2x.its.datastructs.msg.HeaderField;
import org.certificateservices.custom.c2x.its.datastructs.msg.HeaderFieldType;
import org.certificateservices.custom.c2x.its.datastructs.msg.MessageType;
import org.certificateservices.custom.c2x.its.datastructs.msg.Payload;
import org.certificateservices.custom.c2x.its.datastructs.msg.PayloadType;
import org.certificateservices.custom.c2x.its.datastructs.msg.SecuredMessage;

/**
 * Generator to create secured messages.
 * 
 * <p>
 * Encrypted messages are currently not supported
 * <p>
 * If no method i suitable, it is possible to build the secured message manually and sign/encrypt it with the CryptoManager.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class SecuredMessageGenerator {
	
	private CryptoManager cryptoManager;
	private Certificate senderCertificate;
	private PublicKeyAlgorithm signingPublicKeyAlgorithm;
	private PrivateKey senderSigningPrivateKey;
	@SuppressWarnings("unused")
	private PublicKeyAlgorithm encryptionPublicKeyAlgorithm;
	@SuppressWarnings("unused")
	private PrivateKey senderDecryptionPrivateKey;
	
	/**
	 * Main constructor of a Secured Message Generator.
	 * 
	 * @param cryptoManager the currently used CryptoManager
	 * @param senderCertificate certificate used for sending of message.
	 * @param senderSigningPrivateKey signing key used to send messages.
	 * @param encryptionPublicKeyAlgorithm public algorithm used when encryption, null if no encrypted messages are used.
	 * @param senderDecryptionPrivateKey this senders decryption key, null if no encrypted messages are used.
	 * 
	 * @throws IllegalArgumentException if invalid signerInfoType was specified.
	 */
	public SecuredMessageGenerator(CryptoManager cryptoManager, 
			PublicKeyAlgorithm signingPublicKeyAlgorithm,
			Certificate senderCertificate, 
			PrivateKey senderSigningPrivateKey, 
			PublicKeyAlgorithm encryptionPublicKeyAlgorithm,
			PrivateKey senderDecryptionPrivateKey){

		this.cryptoManager = cryptoManager;
		this.senderCertificate = senderCertificate;
		this.senderSigningPrivateKey = senderSigningPrivateKey;
		this.senderDecryptionPrivateKey = senderDecryptionPrivateKey;
		this.signingPublicKeyAlgorithm = signingPublicKeyAlgorithm;
		this.encryptionPublicKeyAlgorithm = encryptionPublicKeyAlgorithm;
	}
	
	/**
	 * Method to generate a signed CAM message(not encrypted) with the following HeaderFields set.
	 * <li>generation_time (current time)
	 * <li>message_type (set to 2)
	 * <li>signer_info (certificate_digest_with_ecdsap256, certificate)
	 * 
	 * @param signerInfoType indicates the type of SignerInfo inserted into generated messages, supported values are:
	 * certificate_digest_with_ecdsap256 or certificate.
	 * @param payLoad the payload to include in the message, null of empty payload (size 0).
	 * @return a signed SecuredMessage with header, payload and trailer fields set.
	 * 
	 *  @throws IllegalArgumentException if supplied arguments was illegal.
	 * @throws SignatureException if internal signature problems occurred.
	 * @throws IOException if communication problems with underlying systems occurred generating the message.
	 */
	public SecuredMessage genSignedCAMMessage(SignerInfoType signerInfoType, byte[] payLoad) throws IllegalArgumentException, SignatureException, IOException{
		List<byte[]> payLoads = null;
		if(payLoad != null){
			payLoads = new ArrayList<byte[]>();
			payLoads.add(payLoad);
		}
		return genSignedCAMMessage(signerInfoType, payLoads);
		
	}
	
	/**
	 * Method to generate a signed CAM message(not encrypted) with the following HeaderFields set.
	 * <li>generation_time (current time)
	 * <li>message_type (set to 2)
	 * <li>signer_info (certificate_digest_with_ecdsap256, certificate)
	 * 
	 * @param signerInfoType indicates the type of SignerInfo inserted into generated messages, supported values are:
	 * certificate_digest_with_ecdsap256 or certificate.
	 * @param payLoads A list of payload types to include in the message, null of emply payload.
	 * @return a signed SecuredMessage with header, payload and trailer fields set.
	 * 
	 * @throws IllegalArgumentException if supplied arguments was illegal.
	 * @throws SignatureException if internal signature problems occurred.
	 * @throws IOException if communication problems with underlying systems occurred generating the message.
	 */
	public SecuredMessage genSignedCAMMessage(SignerInfoType signerInfoType, List<byte[]> payLoads) throws IllegalArgumentException, SignatureException, IOException{
		if(signerInfoType != SignerInfoType.certificate && signerInfoType != SignerInfoType.certificate_digest_with_ecdsap256){
			throw new IllegalArgumentException("Unsupported signer info type: " + signerInfoType);
		}
		
		List<HeaderField> headerFields = new ArrayList<HeaderField>();
		headerFields.add(new HeaderField(new Time64(new Date()))); // generate generation time
        headerFields.add(new HeaderField(MessageType.CAM.getValue())); 
        
		List<Payload> pl = new ArrayList<Payload>();
		if(payLoads == null || payLoads.size() == 0){
			pl.add(new Payload(PayloadType.signed,new byte[0]));
		}else{
			for(byte[] payLoadData : payLoads){
				pl.add(new Payload(PayloadType.signed,payLoadData));
			}
		}
		
		return signMessage(signerInfoType, new SecuredMessage(MessageType.CAM.getSecurityProfile(), headerFields, pl));
		
	}
	
	/**
	 * Method to generate a signed CAM message(not encrypted) with the following HeaderFields set.
	 * <li>generation_time (current time)
	 * <li>message_type (set to 2)
	 * <li>signer_info (certificate_digest_with_ecdsap256, certificate)
	 * 
	 * @param signerInfoType indicates the type of SignerInfo inserted into generated messages, supported values are:
	 * certificate_digest_with_ecdsap256 or certificate.
	 * @param unrecognizedCertificates A list of HashedId3 values of unrecognized certificates.
	 * @return a signed SecuredMessage with header, payload and trailer fields set.
	 * 
	 * @throws IllegalArgumentException if supplied arguments was illegal.
	 * @throws SignatureException if internal signature problems occurred.
	 * @throws IOException if communication problems with underlying systems occurred generating the message.
	 */
	@SuppressWarnings("unchecked")
	public SecuredMessage genSignedCAMUnrecognizedCertificatesMessage(SignerInfoType signerInfoType, List<HashedId3> unrecognizedCertificates) throws IllegalArgumentException, SignatureException, IOException{
		if(signerInfoType != SignerInfoType.certificate && signerInfoType != SignerInfoType.certificate_digest_with_ecdsap256){
			throw new IllegalArgumentException("Unsupported singer info type: " + signerInfoType);
		}
		
		List<HeaderField> headerFields = new ArrayList<HeaderField>();
		headerFields.add(new HeaderField(new Time64(new Date()))); // generate generation time
		headerFields.add(new HeaderField(HeaderFieldType.request_unrecognized_certificate, (List<Encodable>) (List<?>) unrecognizedCertificates));
        headerFields.add(new HeaderField(MessageType.CAM.getValue())); 
		
        
		List<Payload> pl = new ArrayList<Payload>();
		pl.add(new Payload(PayloadType.signed,new byte[0]));
		
		
		return signMessage(signerInfoType,new SecuredMessage(MessageType.CAM.getSecurityProfile(), headerFields, pl));
		
	}
	
	/**
	 * Method to generate a signed DENM message(not encrypted) with the following HeaderFields set.
	 * <li>generation_time (current time)
	 * <li>generation_location (given location)
	 * <li>message_type (set to 1)
	 * <li>signer_info (certificate)
	 * 
	 * @param generationLocation the generation location used in the header field of the message.
	 * @param payLoad the payload to include in the message or null for one empty payload
	 * 
	 * @throws IllegalArgumentException if supplied arguments was illegal.
	 * @throws SignatureException if internal signature problems occurred.
	 * @throws IOException if communication problems with underlying systems occurred generating the message.
	 */
	public SecuredMessage genSignedDENMMessage(ThreeDLocation generationLocation, byte[] payLoad) throws IllegalArgumentException, SignatureException, IOException{
		List<byte[]> payLoads = null;
		if(payLoad != null){
			payLoads = new ArrayList<byte[]>();
			payLoads.add(payLoad);
		}
		return genSignedDENMMessage(generationLocation, payLoads);
		
	}
	
	/**
	 * Method to generate a signed DENM message(not encrypted) with the following HeaderFields set.
	 * <li>generation_time (current time)
	 * <li>generation_location (given location)
	 * <li>message_type (set to 1)
	 * <li>signer_info (certificate)
	 * 
	 * @param generationLocation the generation location used in the header field of the message.
	 * @param payLoads a list of payload to include (all signed) in the message or null for one empty payload
	 * 
	 * @throws IllegalArgumentException if supplied arguments was illegal.
	 * @throws SignatureException if internal signature problems occurred.
	 * @throws IOException if communication problems with underlying systems occurred generating the message.
	 */
	public SecuredMessage genSignedDENMMessage(ThreeDLocation generationLocation, List<byte[]> payLoads) throws IllegalArgumentException, SignatureException, IOException{

		List<HeaderField> headerFields = new ArrayList<HeaderField>();
		headerFields.add(new HeaderField(new Time64(new Date()))); // generate generation time
		headerFields.add(new HeaderField(generationLocation));
        headerFields.add(new HeaderField(MessageType.DENM.getValue()));

        
		List<Payload> pl = new ArrayList<Payload>();
		if(payLoads == null || payLoads.size() == 0){
			pl.add(new Payload(PayloadType.signed,new byte[0]));
		}else{
			for(byte[] payLoadData : payLoads){
				pl.add(new Payload(PayloadType.signed,payLoadData));
			}
		}
		
		return signMessage(SignerInfoType.certificate,new SecuredMessage(MessageType.DENM.getSecurityProfile(), headerFields, pl));
		
	}
	

	
	/**
	 * Generate and attaches a signature to the given secured message.
	 */
	protected SecuredMessage signMessage(SignerInfoType signerInfoType,SecuredMessage securedMessage) throws IOException, IllegalArgumentException, SignatureException{
		return cryptoManager.signSecureMessage(securedMessage,senderCertificate, signerInfoType, signingPublicKeyAlgorithm, senderSigningPrivateKey);		
	}
}
