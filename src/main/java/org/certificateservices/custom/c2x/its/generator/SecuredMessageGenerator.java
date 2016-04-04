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
import org.certificateservices.custom.c2x.its.crypto.ITSCryptoManager;
import org.certificateservices.custom.c2x.its.datastructs.basic.HashedId3;
import org.certificateservices.custom.c2x.its.datastructs.basic.IntX;
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
 * If no method i suitable, it is possible to build the secured message manually and sign/encrypt it with the CryptoManager.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class SecuredMessageGenerator {
	
	public static final long ITS_AID_CAM = 36;
	public static final long ITS_AID_DENM = 37;
	
	private ITSCryptoManager cryptoManager;
	private Certificate senderCertificate;
	Certificate[] senderCACertificates;
	private PublicKeyAlgorithm signingPublicKeyAlgorithm;
	private PrivateKey senderSigningPrivateKey;
	@SuppressWarnings("unused")
	private PublicKeyAlgorithm encryptionPublicKeyAlgorithm;
	@SuppressWarnings("unused")
	private PrivateKey senderDecryptionPrivateKey;
	private int certificateVersion = Certificate.DEFAULT_CERTIFICATE_VERSION;
	private int protocolVersion = SecuredMessage.DEFAULT_PROTOCOL;
	
	/**
	 * Main constructor of a Secured Message Generator.
	 * 
	 * @param cryptoManager the currently used CryptoManager
	 * @param senderCertificate certificate used for sending of message.
	 * @param signerCACertificates the CA certificate chain of the signer certificate, up to but not including trust chain, used 
	 * if the signed info certificate_chain, otherwise it can be null. The top-most CA should be first and the CA signing the end user certificate last.
	 * @param senderSigningPrivateKey signing key used to send messages.
	 * @param encryptionPublicKeyAlgorithm public algorithm used when encryption, null if no encrypted messages are used.
	 * @param senderDecryptionPrivateKey this senders decryption key, null if no encrypted messages are used.
	 * 
	 * @throws IllegalArgumentException if invalid signerInfoType was specified.
	 */
	public SecuredMessageGenerator(ITSCryptoManager cryptoManager, 
			PublicKeyAlgorithm signingPublicKeyAlgorithm,
			Certificate senderCertificate, 
			Certificate[] senderCACertificates,
			PrivateKey senderSigningPrivateKey, 
			PublicKeyAlgorithm encryptionPublicKeyAlgorithm,
			PrivateKey senderDecryptionPrivateKey){
		this(SecuredMessage.DEFAULT_PROTOCOL,Certificate.DEFAULT_CERTIFICATE_VERSION, cryptoManager, signingPublicKeyAlgorithm, senderCertificate, 
				senderCACertificates,senderSigningPrivateKey, encryptionPublicKeyAlgorithm, senderDecryptionPrivateKey);
	}
	
	/**
	 * Constructor of a Secured Message Generator where certificate version is specified.
	 * 
	 * @param protocolVersion the version of secured messages generated.
	 * @param certificateVersion the version of related certificates for see Certificate.CERTIFICATE_VERSION_ constants.
	 * @param cryptoManager the currently used CryptoManager
	 * @param senderCertificate certificate used for sending of message.
	 * @param signerCACertificates the CA certificate chain of the signer certificate, up to but not including trust chain, used 
	 * if the signed info certificate_chain, otherwise it can be null. The top-most CA should be first and the CA signing the end user certificate last.
	 * @param senderSigningPrivateKey signing key used to send messages.
	 * @param encryptionPublicKeyAlgorithm public algorithm used when encryption, null if no encrypted messages are used.
	 * @param senderDecryptionPrivateKey this senders decryption key, null if no encrypted messages are used.
	 * 
	 * @throws IllegalArgumentException if invalid signerInfoType was specified.
	 */
	public SecuredMessageGenerator(int protocolVersion,
			int certificateVersion,
			ITSCryptoManager cryptoManager, 
			PublicKeyAlgorithm signingPublicKeyAlgorithm,
			Certificate senderCertificate, 
			Certificate[] senderCACertificates,
			PrivateKey senderSigningPrivateKey, 
			PublicKeyAlgorithm encryptionPublicKeyAlgorithm,
			PrivateKey senderDecryptionPrivateKey){
		this.protocolVersion = protocolVersion;
		this.certificateVersion = certificateVersion;
		this.cryptoManager = cryptoManager;
		this.senderCertificate = senderCertificate;
		this.senderCACertificates = senderCACertificates;
		this.senderSigningPrivateKey = senderSigningPrivateKey;
		this.senderDecryptionPrivateKey = senderDecryptionPrivateKey;
		this.signingPublicKeyAlgorithm = signingPublicKeyAlgorithm;
		this.encryptionPublicKeyAlgorithm = encryptionPublicKeyAlgorithm;
	}
	
	/**
	 * Method to generate a signed CAM message(not encrypted) depending on protocol version initialized
	 * with this generator.
	 * 
	 * @param signerInfoType indicates the type of SignerInfo inserted into generated messages, supported values are:
	 * certificate_digest_with_ecdsap256 or certificate.
	 * @param payLoad the payload to include in the message, null of empty payload (size 0).
	 * @return a signed SecuredMessage with header, payload and trailer fields set.
	 * 
	 * @throws IllegalArgumentException if supplied arguments was illegal.
	 * @throws SignatureException if internal signature problems occurred.
	 * @throws IOException if communication problems with underlying systems occurred generating the message.
	 */
	public SecuredMessage genSignedCAMMessage(SignerInfoType signerInfoType, byte[] payLoad) throws IllegalArgumentException, SignatureException, IOException{
		if(protocolVersion == SecuredMessage.PROTOCOL_VERSION_1){
			List<byte[]> payLoads = new ArrayList<byte[]>();
			if(payLoad != null){
			  payLoads.add(payLoad);
			}
			return genVer1SignedCAMMessage(signerInfoType, payLoads);
		}else{
			return genVer2SignedCAMMessage(signerInfoType, payLoad);
		}
		
	}
	
	/**
	 * Method to generate a signed CAM message(not encrypted) with the following HeaderFields set.
	 * <li>generation_time (current time)
	 * <li>its_aid (set to 36)
	 * <li>signer_info (certificate_digest_with_ecdsap256, certificate or certificate_chain)
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
	private SecuredMessage genVer2SignedCAMMessage(SignerInfoType signerInfoType, byte[] payLoad) throws IllegalArgumentException, SignatureException, IOException{
		if(signerInfoType != SignerInfoType.certificate && signerInfoType != SignerInfoType.certificate_digest_with_ecdsap256
				&& signerInfoType != SignerInfoType.certificate_chain){
			throw new IllegalArgumentException("Unsupported signer info type: " + signerInfoType);
		}
		
		List<HeaderField> headerFields = new ArrayList<HeaderField>();
		headerFields.add(new HeaderField(protocolVersion,new Time64(certificateVersion, new Date()))); // generate generation time
        headerFields.add(new HeaderField(protocolVersion,new IntX(ITS_AID_CAM))); 
        
        Payload pl;
		if(payLoad == null){
			pl = new Payload(PayloadType.signed,new byte[0]);
		}else{
		    pl = new Payload(PayloadType.signed,payLoad);
		}
		
		return signMessage(signerInfoType, new SecuredMessage(headerFields, pl));
		
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
	public SecuredMessage genVer1SignedCAMMessage(SignerInfoType signerInfoType, List<byte[]> payLoads) throws IllegalArgumentException, SignatureException, IOException{
		
		if(signerInfoType != SignerInfoType.certificate && signerInfoType != SignerInfoType.certificate_digest_with_ecdsap256){
			throw new IllegalArgumentException("Unsupported signer info type: " + signerInfoType);
		}
		
		List<HeaderField> headerFields = new ArrayList<HeaderField>();
		headerFields.add(new HeaderField(1,new Time64(certificateVersion, new Date()))); // generate generation time
        headerFields.add(new HeaderField(1,MessageType.CAM.getValue())); 
        
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
	 * 
	 * For Version 1 Messages
	 * <li>generation_time (current time)
	 * <li>message_type (set to 2)
	 * <li>signer_info (certificate_digest_with_ecdsap256, certificate)
	 * 
	 * For Version 2 Messages
	 * <li>generation_time (current time)
	 * <li>its_aid set to 37
	 * <li>signer_info (certificate_digest_with_ecdsap256, certificate, certificate_chain)
	 * 
	 * @param signerInfoType indicates the type of SignerInfo inserted into generated messages, supported values are:
	 * certificate_digest_with_ecdsap256, certificate or certificate_chain (Ver 2 only).
	 * @param unrecognizedCertificates A list of HashedId3 values of unrecognized certificates.
	 * @return a signed SecuredMessage with header, payload and trailer fields set.
	 * 
	 * @throws IllegalArgumentException if supplied arguments was illegal.
	 * @throws SignatureException if internal signature problems occurred.
	 * @throws IOException if communication problems with underlying systems occurred generating the message.
	 */
	@SuppressWarnings("unchecked")
	public SecuredMessage genSignedCAMUnrecognizedCertificatesMessage(SignerInfoType signerInfoType, List<HashedId3> unrecognizedCertificates) throws IllegalArgumentException, SignatureException, IOException{
		if(signerInfoType != SignerInfoType.certificate && 
		   signerInfoType != SignerInfoType.certificate_digest_with_ecdsap256 &&
		   signerInfoType != SignerInfoType.certificate_chain){
			throw new IllegalArgumentException("Unsupported signer info type: " + signerInfoType);
		}
		
		if(protocolVersion == SecuredMessage.PROTOCOL_VERSION_1 && signerInfoType == SignerInfoType.certificate_chain){
			throw new IllegalArgumentException("Unsupported signer info type: " + signerInfoType + " for version 1 protocol.");
		}
		
		List<HeaderField> headerFields = new ArrayList<HeaderField>();
		headerFields.add(new HeaderField(protocolVersion,new Time64(certificateVersion,new Date()))); // generate generation time
		headerFields.add(new HeaderField(protocolVersion,HeaderFieldType.request_unrecognized_certificate, (List<Encodable>) (List<?>) unrecognizedCertificates));
		if(protocolVersion == SecuredMessage.PROTOCOL_VERSION_1){
          headerFields.add(new HeaderField(protocolVersion,MessageType.CAM.getValue()));
		}else{
		  headerFields.add(new HeaderField(protocolVersion,new IntX(ITS_AID_CAM)));
		}
        
		Payload payload = new Payload(PayloadType.signed,new byte[0]);
		
		SecuredMessage sm;
		if(protocolVersion == SecuredMessage.PROTOCOL_VERSION_1){
			List<Payload> pl = new ArrayList<Payload>();
			pl.add(payload);
			sm = new SecuredMessage(MessageType.CAM.getSecurityProfile(), headerFields, pl);
		}else{
			sm = new SecuredMessage(headerFields, payload);
		}
		return signMessage(signerInfoType,sm);
		
	}
	
	/**
	 * Method to generate a signed DENM message(not encrypted) depending on the version set in
	 * the message generator.
	 * 
	 * @param generationLocation the generation location used in the header field of the message.
	 * @param payLoad the payload to include in the message or null for one empty payload
	 * 
	 * @throws IllegalArgumentException if supplied arguments was illegal.
	 * @throws SignatureException if internal signature problems occurred.
	 * @throws IOException if communication problems with underlying systems occurred generating the message.
	 */
	public SecuredMessage genSignedDENMMessage(ThreeDLocation generationLocation, byte[] payLoad) throws IllegalArgumentException, SignatureException, IOException{
		if(protocolVersion == SecuredMessage.PROTOCOL_VERSION_1){
			List<byte[]> payLoads = new ArrayList<byte[]>();
			if(payLoad != null){
			  payLoads.add(payLoad);
			}
			return genVer1SignedDENMMessage(generationLocation, payLoads);
		}else{
			return genVer2SignedDENMMessage(generationLocation, payLoad);
		}
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
	public SecuredMessage genVer1SignedDENMMessage(ThreeDLocation generationLocation, List<byte[]> payLoads) throws IllegalArgumentException, SignatureException, IOException{

		List<HeaderField> headerFields = new ArrayList<HeaderField>();
		headerFields.add(new HeaderField(protocolVersion,new Time64(certificateVersion,new Date()))); // generate generation time
		headerFields.add(new HeaderField(protocolVersion,generationLocation));
        headerFields.add(new HeaderField(protocolVersion,MessageType.DENM.getValue()));

        
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
	 * Method to generate a Version 2 signed DENM message(not encrypted) with the following HeaderFields set.
	 * <li>generation_time (current time)
	 * <li>generation_location (given location)
	 * <li>its_aid (set to 37)
	 * <li>signer_info (certificate)
	 * 
	 * @param generationLocation the generation location used in the header field of the message.
	 * @param payLoads a list of payload to include (all signed) in the message or null for one empty payload
	 * 
	 * @throws IllegalArgumentException if supplied arguments was illegal.
	 * @throws SignatureException if internal signature problems occurred.
	 * @throws IOException if communication problems with underlying systems occurred generating the message.
	 */
	public SecuredMessage genVer2SignedDENMMessage(ThreeDLocation generationLocation, byte[] payLoad) throws IllegalArgumentException, SignatureException, IOException{

		List<HeaderField> headerFields = new ArrayList<HeaderField>();
		headerFields.add(new HeaderField(protocolVersion,new Time64(certificateVersion,new Date()))); // generate generation time
		headerFields.add(new HeaderField(protocolVersion,generationLocation));
        headerFields.add(new HeaderField(protocolVersion,new IntX(ITS_AID_DENM)));

        
		Payload pl;
		if(payLoad == null){
			pl = new Payload(PayloadType.signed,new byte[0]);
		}else{
			pl = new Payload(PayloadType.signed,payLoad);
		}
		
		return signMessage(SignerInfoType.certificate,new SecuredMessage(headerFields, pl));
		
	}

	
	/**
	 * Generate and attaches a signature to the given secured message.
	 */
	protected SecuredMessage signMessage(SignerInfoType signerInfoType,SecuredMessage securedMessage) throws IOException, IllegalArgumentException, SignatureException{
		return cryptoManager.signSecureMessage(securedMessage,senderCertificate, senderCACertificates, signerInfoType, signingPublicKeyAlgorithm, senderSigningPrivateKey);		
	}
	

}
