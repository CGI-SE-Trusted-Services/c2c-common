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
package org.certificateservices.custom.c2x.ieee1609dot2.generator;

import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.certificateservices.custom.c2x.asn1.coer.COEREncodable;
import org.certificateservices.custom.c2x.asn1.coer.COEROctetStream;
import org.certificateservices.custom.c2x.common.crypto.AlgorithmIndicator;
import org.certificateservices.custom.c2x.common.crypto.ECQVHelper;
import org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.*;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.BasePublicEncryptionKey.BasePublicEncryptionKeyChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EccP256CurvePoint.EccP256CurvePointChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature.SignatureChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.CertificateType;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.SequenceOfCertificate;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.*;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.RecipientInfo.RecipientInfoChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.*;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.HashedData.HashedDataChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.Ieee1609Dot2Content.Ieee1609Dot2ContentChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.SignerIdentifier.SignerIdentifierChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.receiver.Receiver;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.recipient.Recipient;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.*;



/**
 * Base CertGenerator class containing common methods.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */

public class SecuredDataGenerator {
	
	public static int DEFAULT_VERSION = Ieee1609Dot2Data.DEFAULT_VERSION;
	/**
	 * Class indicating what kind for signer identifier that should be included in a signed secure data.
	 * @author Philip Vendil
	 *
	 */
	public enum SignerIdentifierType{
		/**
		 * Include a hash reference to the certificate only.
		 */
		HASH_ONLY,
		/**
		 * Include the signer certificate only.
		 */
		SIGNER_CERTIFICATE,
		/**
		 * Include the entire certificate chain up to (but not including) the trust anchor.
		 */
		CERT_CHAIN,
		/**
		 * Signer identifier should be set to self.
		 */
		SELF
	}

	Ieee1609Dot2CryptoManager cryptoManager = null;
	int version;
	HashAlgorithm hashAlgorithm;
	ECQVHelper ecqvHelper;	
	SignatureChoices signAlgorithm;
	CertChainBuilder certChainBuilder;

	/**
	 * Main constructor.
	 * 
	 * @param version version if Ieee1609Dot2Data to generate.
	 * @param cryptoManager the related crypto manager
	 * @param hashAlgorithm the related hash algorithm used in messages
	 * @param signAlgorithm the related sign algorithm used in messages.
	 * @throws SignatureException if internal problems occurred initializing the generator.
	 */
	public SecuredDataGenerator(int version, Ieee1609Dot2CryptoManager cryptoManager, HashAlgorithm hashAlgorithm, SignatureChoices signAlgorithm) throws SignatureException{
		this.cryptoManager = cryptoManager;
		this.version = version;
		this.hashAlgorithm = hashAlgorithm;
		this.signAlgorithm = signAlgorithm;
		
		ecqvHelper = new ECQVHelper(cryptoManager);
		certChainBuilder = new CertChainBuilder(cryptoManager);
	}

	/**
	 * Method to generate a Signed Ieee1609Dot2Data.
	 *
	 * @param hi the header information data to include.
	 * @param message the message data to sign.
	 * @param signerIdentifierType type of signer identifier to include, one of SignerIdentifierType
	 * @param signerCertificateChain the complete chain up to the trust anchor. Important the trust anchor MUST be an explicit certificate and the array
	 * must be in the order of end entity certificate at position 0 and trust anchor last in array.
	 * @param signerPrivateKey private key of signer.
	 * @return a signed Ieee1609Dot2Data structure.
	 * @throws IllegalArgumentException if fault was discovered in supplied parameters.
	 * @throws SignatureException if internal problems occurred generating the signature.
	 * @throws IOException if IO exception occurred communicating with underlying systems.
	 */
	public Ieee1609Dot2Data genSignedData(HeaderInfo hi, byte[] message, SignerIdentifierType signerIdentifierType, Certificate[] signerCertificateChain, PrivateKey signerPrivateKey) throws IllegalArgumentException, SignatureException, IOException{
		assert signerIdentifierType != SignerIdentifierType.SELF;
		try {
			return genSignedData(hi, message, signerIdentifierType, signerCertificateChain, getSignerPublicKey(signerCertificateChain), signerPrivateKey);
		} catch (InvalidKeySpecException e) {
		  throw new SignatureException("Error signing message, invalid key spec: " + e.getMessage(),e);
	    }
	}

	/**
	 * Method to generate a Signed Ieee1609Dot2Data signerIdentifierType SELF
	 *
	 * @param hi the header information data to include.
	 * @param message the message data to sign.
	 * must be in the order of end entity certificate at position 0 and trust anchor last in array.
	 * @param signerPrivateKey private key of signer.
	 * @return a signed Ieee1609Dot2Data structure.
	 * @throws IllegalArgumentException if fault was discovered in supplied parameters.
	 * @throws SignatureException if internal problems occurred generating the signature.
	 * @throws IOException if IO exception occurred communicating with underlying systems.
	 */
	public Ieee1609Dot2Data genSignedData(HeaderInfo hi, byte[] message, PublicKey signPublicKey, PrivateKey signerPrivateKey) throws IllegalArgumentException, SignatureException, IOException{
		return genSignedData(hi, message, SignerIdentifierType.SELF, null, signPublicKey, signerPrivateKey);
	}

	/**
	 * Method to generate a Signed Ieee1609Dot2Data.
	 * 
	 * @param hi the header information data to include.
	 * @param message the message data to sign.
	 * @param signerIdentifierType type of signer identifier to include, one of SignerIdentifierType
	 * @param signerCertificateChain the complete chain up to the trust anchor. Important the trust anchor MUST be an explicit certificate and the array
	 * must be in the order of end entity certificate at position 0 and trust anchor last in array.
	 * @param signerPrivateKey private key of signer.
	 * @return a signed Ieee1609Dot2Data structure.
	 * @throws IllegalArgumentException if fault was discovered in supplied parameters.
	 * @throws SignatureException if internal problems occurred generating the signature.
	 * @throws IOException if IO exception occurred communicating with underlying systems. 
	 */
	protected Ieee1609Dot2Data genSignedData(HeaderInfo hi, byte[] message, SignerIdentifierType signerIdentifierType, Certificate[] signerCertificateChain, PublicKey signPublicKey, PrivateKey signerPrivateKey) throws IllegalArgumentException, SignatureException, IOException{
		
		try{
			Ieee1609Dot2Data unsecuredData = new Ieee1609Dot2Data(version,new Ieee1609Dot2Content(Ieee1609Dot2ContentChoices.unsecuredData, new Opaque(message)));
			ToBeSignedData tbsData = new ToBeSignedData(new SignedDataPayload(unsecuredData, null), hi);

			return genSignedDataStructure(tbsData, signerIdentifierType, signerCertificateChain, signPublicKey, signerPrivateKey, true);
		}catch(NoSuchAlgorithmException e){
			throw new SignatureException("Error signing message, no such algorithm: " + e.getMessage(),e);
		} catch (InvalidKeySpecException e) {
			throw new SignatureException("Error signing message, invalid key spec: " + e.getMessage(),e);
		}
	
	}
	
	/**
	 * Method to generate a Signed Ieee1609Dot2Data where only a hash of the data is included as reference.
	 * 
	 * @param hi the header information data to include.
	 * @param message the message data to sign.
	 * @param signerIdentifierType type of signer identifier to include, one of SignerIdentifierType
	 * @param signerCertificateChain the complete chain up to the trust anchor. Important the trust anchor MUST be an explicit certificate and the array
	 * must be in the order of end entity certificate at position 0 and trust anchor last in array.
	 * @param signerPrivateKey private key of signer.
	 * @return a signed Ieee1609Dot2Data structure.
	 * @throws IllegalArgumentException if fault was discovered in supplied parameters.
	 * @throws SignatureException if internal problems occurred generating the signature.
	 * @throws IOException if IO exception occurred communicating with underlying systems. 
	 */
	public Ieee1609Dot2Data genReferencedSignedData(HeaderInfo hi, byte[] message, SignerIdentifierType signerIdentifierType, Certificate[] signerCertificateChain, PrivateKey signerPrivateKey) throws IllegalArgumentException, SignatureException, IOException{
		
		try{
			HashedData hashedData = new HashedData(getHashedDataChoice(), cryptoManager.digest(message, hashAlgorithm));
			ToBeSignedData tbsData = new ToBeSignedData(new SignedDataPayload(null, hashedData), hi);

			return genSignedDataStructure(tbsData, signerIdentifierType, signerCertificateChain, getSignerPublicKey(signerCertificateChain), signerPrivateKey, false);
		}catch(NoSuchAlgorithmException e){
			throw new SignatureException("Error signing message, no such algorithm: " + e.getMessage(),e);
		} catch (InvalidKeySpecException e) {
			throw new IllegalArgumentException("Error signing message, invalid key spec: " + e.getMessage(),e);
		}
	}
	
	/**
	 * Method to build a cert store map of HashedId8 to Certificate from a collection of certificates.
	 * @param certificates the collection of certificate to build store of.
	 * @return a map of HashedId8 to certificate.
	 */
	public Map<HashedId8, Certificate> buildCertStore(Collection<Certificate> certificates) throws IllegalArgumentException, NoSuchAlgorithmException, IOException{
		Map<HashedId8, Certificate> retval = new HashMap<HashedId8, Certificate>();
		for(Certificate cert : certificates){
			// Implicit certificate only supports ECDSA 256 since the reconstruction value is of type ECP256CurvePoint.
			AlgorithmIndicator alg = cert.getSignature() != null ? cert.getSignature().getType() : HashAlgorithm.sha256;
			retval.put(new HashedId8(cryptoManager.digest(cert.getEncoded(), alg)), cert);
		}
		
		return retval;
	}
	
	/**
	 * Method to build a cert store map of HashedId8 to Certificate from an array of certificates.
	 * @param certificates the array of certificate to build store of.
	 * @return a map of HashedId8 to certificate.
	 */
    public Map<HashedId8, Certificate> buildCertStore(Certificate[] certificates) throws IllegalArgumentException, NoSuchAlgorithmException, IOException{
	  	return buildCertStore(Arrays.asList(certificates));
	}
   
    /**
     * Method to build a store of receiver in order of a hashedId8 -> Receiver
     * 
     * @param receivers collection of receivers to build map of.
     * @return a map of hashedId8 -> receiver
     */
    public Map<HashedId8, Receiver> buildRecieverStore(Collection<Receiver> receivers) throws IllegalArgumentException, IOException, GeneralSecurityException{
		Map<HashedId8, Receiver> retval = new HashMap<HashedId8, Receiver>();
		for(Receiver r : receivers){
		    retval.put(r.getReference(r.getHashAlgorithm(),cryptoManager), r);
		}
		
		return retval;
	} 
    

    
    /**
     * Method to build a store of receiver in order of a hashedId8 -> Receiver map from an array.
     * 
     * @param receivers array of receivers to build map of.
     * @return a map of hashedId8 -> Receivers
     */
    public Map<HashedId8, Receiver> buildRecieverStore(Receiver[] receivers) throws IllegalArgumentException, GeneralSecurityException, IOException{
    	return buildRecieverStore(Arrays.asList(receivers));
	} 
	

    

    
    /**
     * Method to verify a signed data, method only verifies the signature, it doesn't validate it by permissions, validity or geographically.
     * @param signedData the signed data to verify.
     * @param certStore a list of known certificates that can be used to build a certificate path (excluding trust anchors).
     * @param trustStore certificates in trust store, must be explicit certificate in order to qualify as trust anchors.
     * @return true if data structure signature verifies.
     * 
	 * @throws IllegalArgumentException if fault was discovered in supplied parameters.
	 * @throws SignatureException if internal problems occurred verifying the signature.
	 * @throws IOException if IO exception occurred communicating with underlying systems. 
     */
	public boolean verifySignedData(Ieee1609Dot2Data signedData, Map<HashedId8, Certificate> certStore, Map<HashedId8, Certificate> trustStore) throws IllegalArgumentException, SignatureException, IOException{

		if(signedData.getContent().getType() != Ieee1609Dot2ContentChoices.signedData){
			throw new IllegalArgumentException("Only signed Ieee1609Dot2Data can verified");
		}
		
		try{
			SignedData sd = (SignedData) signedData.getContent().getValue();
			if(sd.getTbsData().getPayload().getData() == null){
				throw new IllegalArgumentException("Error no enveloped data found in Signed Payload");
			}
			HashedId8 signerId = getSignerId(sd.getSigner());
			Map<HashedId8, Certificate> signedDataStore = getSignedDataStore(sd.getSigner());
			Certificate[] signerCertChain = certChainBuilder.buildChain(signerId, signedDataStore, certStore, trustStore);
			PublicKey signerPublicKey = getSignerPublicKey(signerCertChain);
			return cryptoManager.verifySignature(sd.getTbsData().getEncoded(), sd.getSignature(), signerCertChain[0], signerPublicKey);
		}catch(NoSuchAlgorithmException e){
			throw new SignatureException("Error verifying message, no such algorithm found when verifing signed data: " + e.getMessage(),e);
		} catch (InvalidKeySpecException e) {
			throw new IllegalArgumentException("Error verifying message, invalid key spec: " + e.getMessage(),e);
		}
	}

	/**
	 * Method to verify a signed data against a specific public key. The method only verifies the signature, it doesn't validate it by permissions, validity or geographically.
	 * @param signedData the signed data to verify.
	 * @param signerPublicKey the public key of the signer.
	 * @return true if data structure signature verifies.
	 *
	 * @throws IllegalArgumentException if fault was discovered in supplied parameters.
	 * @throws SignatureException if internal problems occurred verifying the signature.
	 * @throws IOException if IO exception occurred communicating with underlying systems.
	 */
	public boolean verifySignedData(Ieee1609Dot2Data signedData, PublicKey signerPublicKey) throws IllegalArgumentException, SignatureException, IOException{
		if(signedData.getContent().getType() != Ieee1609Dot2ContentChoices.signedData){
			throw new IllegalArgumentException("Only signed Ieee1609Dot2Data can verified");
		}

		SignedData sd = (SignedData) signedData.getContent().getValue();
		if(sd.getTbsData().getPayload().getData() == null){
			throw new IllegalArgumentException("Error no enveloped data found in Signed Payload");
		}

		return cryptoManager.verifySelfSignedSignature(sd.getTbsData().getEncoded(), sd.getSignature(),  signerPublicKey);
	}

    /**
     * Method to verify a signed data, method only verifies the signature, it doesn't validate it by permissions, validity or geographically.
     * @param signedData the signed data to verify.
     * @param referencedData the signature refers to.
     * @param certStore a list of known certificates that can be used to build a certificate path (excluding trust anchors).
     * @param trustStore certificates in trust store, must be explicit certificate in order to qualify as trust anchors.
     * @return true if data structure signature verifies.
     * 
	 * @throws IllegalArgumentException if fault was discovered in supplied parameters.
	 * @throws SignatureException if internal problems occurred verifying the signature.
	 * @throws IOException if IO exception occurred communicating with underlying systems. 
     */
	public boolean verifyReferencedSignedData(Ieee1609Dot2Data signedData, byte[] referencedData, Map<HashedId8, Certificate> certStore, Map<HashedId8, Certificate> trustStore) throws IllegalArgumentException, SignatureException, IOException{

		if(signedData.getContent().getType() != Ieee1609Dot2ContentChoices.signedData){
			throw new IllegalArgumentException("Only signed Ieee1609Dot2Data can verified");
		}
		
		try{
			SignedData sd = (SignedData) signedData.getContent().getValue();
			if(sd.getTbsData().getPayload().getExtDataHash() == null){
				throw new IllegalArgumentException("Error no external hash reference found in Signed Payload");
			}
			HashedData hashedData = sd.getTbsData().getPayload().getExtDataHash();
			if(!Arrays.equals(((COEROctetStream) hashedData.getValue()).getData(), cryptoManager.digest(referencedData, hashAlgorithm))){
			  return false;	
			}
			HashedId8 signerId = getSignerId(sd.getSigner());
			Map<HashedId8, Certificate> signedDataStore = getSignedDataStore(sd.getSigner());
			Certificate[] signerCertChain = certChainBuilder.buildChain(signerId, signedDataStore, certStore, trustStore);
			PublicKey signerPublicKey = getSignerPublicKey(signerCertChain);
			return cryptoManager.verifySignature(sd.getTbsData().getEncoded(), sd.getSignature(), signerCertChain[0], signerPublicKey);
		}catch(NoSuchAlgorithmException e){
			throw new SignatureException("Error verifying message, no such algorithm found when verifing signed data: " + e.getMessage(),e);
		} catch (InvalidKeySpecException e) {
			throw new IllegalArgumentException("Error verifying message, invalid key spec: " + e.getMessage(),e);
		}
	}
	
	/**
	 * Method to encrypt data with a shared key.
	 * 
	 * @param alg symmetric key algorithm indicator.
	 * @param data  data to encrypt
	 * @param preSharedKey the preshared key.
	 * @return an encrypted Ieee1609Dot2Data structure.
	 * @throws IllegalArgumentException if one of the argument was invalid.
	 * @throws GeneralSecurityException if internal problems occurred encrypting the data.
	 * @throws IOException if communication problems occurred when encrypting the data.
	 */
	public Ieee1609Dot2Data encryptDataWithPresharedKey(AlgorithmIndicator alg, byte[] data, SecretKey preSharedKey) throws IllegalArgumentException, GeneralSecurityException, IOException{
		HashedId8 keyId = getSecretKeyID(alg,preSharedKey);
		
		byte[] nounce = cryptoManager.genNounce(alg);
		byte[] cipherText = cryptoManager.symmetricEncryptIEEE1609_2_2017(alg, data, preSharedKey.getEncoded(), nounce);
		
		RecipientInfo ri1 = new RecipientInfo(new PreSharedKeyRecipientInfo(keyId.getData()));
		SequenceOfRecipientInfo recipients = new SequenceOfRecipientInfo(new RecipientInfo[] {ri1});
		
		AesCcmCiphertext aesCcmCiphertext = new AesCcmCiphertext(nounce, cipherText); 
		SymmetricCiphertext symmetricCiphertext = new SymmetricCiphertext(aesCcmCiphertext);
		EncryptedData encData = new EncryptedData(recipients, symmetricCiphertext);
		
		Ieee1609Dot2Content content = new Ieee1609Dot2Content(encData);
		return newEncryptedDataStructure(version, content);
	}
	
	/**
	 * Method to encrypt data to a list of receipients.
	 * 
	 * @param alg algorithm indicating which symmetric and depending on encryption method which asymmetric algorithm to use.
	 * @param data the data to encrypt
	 * @param recipients a list of recipients, all recipients should be a Recipient implementation and be of the same type.
	 * 
	 * @return an encrypted Ieee1609Dot2Data structure.
	 * @throws IllegalArgumentException if one of the argument was invalid.
	 * @throws GeneralSecurityException if internal problems occurred encrypting the data.
	 * @throws IOException if communication problems occurred when encrypting the data.
	 */
	public EncryptResult encryptData(AlgorithmIndicator alg,byte[] data,Recipient[] recipients) throws IllegalArgumentException, GeneralSecurityException, IOException{
		SecretKey encryptionKey = cryptoManager.generateSecretKey(alg);
		byte[] nounce = cryptoManager.genNounce(alg);
		byte[] cipherText = cryptoManager.symmetricEncryptIEEE1609_2_2017(alg, data, encryptionKey.getEncoded(), nounce);
		
		RecipientInfo[] ris = new RecipientInfo[recipients.length];
		for(int i=0;i<recipients.length;i++){
			ris[i] = recipients[i].toRecipientInfo(alg, cryptoManager, encryptionKey);
		}
		SequenceOfRecipientInfo recSeq = new SequenceOfRecipientInfo(ris);
		
		AesCcmCiphertext aesCcmCiphertext = new AesCcmCiphertext(nounce, cipherText); 
		SymmetricCiphertext symmetricCiphertext = new SymmetricCiphertext(aesCcmCiphertext);
		EncryptedData encData = new EncryptedData(recSeq, symmetricCiphertext);
		
		Ieee1609Dot2Content content = new Ieee1609Dot2Content(encData);
		return new EncryptResult(encryptionKey, newEncryptedDataStructure(version, content));
	}

	/**
	 * Method to decrypt a message using a given set of receivers.
	 * Receiver store can be created with buildRecieverStore method.
	 *
	 * Method returns the symmetrical private key that was used to decrypt the message.
	 *
	 * @param encryptedData the data to decrypt.
	 * @param recieverStore the store of known receiver keys.
	 *
	 * @return the decrypted payload.
	 *
	 * @throws IllegalArgumentException if one of the argument was invalid.
	 * @throws GeneralSecurityException if internal problems occurred decrypting the data.
	 * @throws IOException if communication problems occurred when decrypting the data.
	 */
	public DecryptResult decryptDataWithSecretKey(Ieee1609Dot2Data encryptedData,Map<HashedId8, Receiver> recieverStore) throws IllegalArgumentException, GeneralSecurityException, IOException{
		if(encryptedData.getContent().getType() != Ieee1609Dot2Content.Ieee1609Dot2ContentChoices.encryptedData){
			throw new IllegalArgumentException("Error invalid Ieee1609Dot2Data content, " + encryptedData.getContent().getType() +" only type encryptedData can be decrypted.");
		}

		if(recieverStore == null){
			throw new IllegalArgumentException("Error ReceiverStore cannot be empty.");
		}
		EncryptedData ed = (EncryptedData) encryptedData.getContent().getValue();
		COEREncodable[] recipientInfos =(COEREncodable[]) ed.getRecipients().getSequenceValues();

		SecretKey decryptionKey = null;

		for(COEREncodable ri : recipientInfos){
			HashedId8 reference = getReference((RecipientInfo) ri);
			Receiver reciever = recieverStore.get(reference);
			if(reciever != null){
				decryptionKey = reciever.extractDecryptionKey(cryptoManager, (RecipientInfo) ri);
				if(decryptionKey != null){
					break;
				}
			}
		}

		if(decryptionKey == null){
			throw new IllegalArgumentException("Error decrypting data, no matching Reciever info could be found to retrieve the decryption key.");
		}

		SymmetricCiphertext symmetricCiphertext = ed.getCipherText();

		byte[] data = cryptoManager.symmetricDecryptIEEE1609_2_2017(symmetricCiphertext.getType(), getEncryptedData(symmetricCiphertext), decryptionKey.getEncoded(), getNounce(symmetricCiphertext));
		return new DecryptResult(decryptionKey,data);
	}
	/**
	 * Method to decrypt a message using a given set of receivers. Receiver store can be created with buildRecieverStore method.
	 * 
	 * @param encryptedData the data to decrypt.
	 * @param recieverStore the store of known receiver keys.
	 * 
	 * @return the decrypted payload.
	 * 
	 * @throws IllegalArgumentException if one of the argument was invalid.
	 * @throws GeneralSecurityException if internal problems occurred decrypting the data.
	 * @throws IOException if communication problems occurred when decrypting the data.
	 */
	public byte[] decryptData(Ieee1609Dot2Data encryptedData,Map<HashedId8, Receiver> recieverStore) throws IllegalArgumentException, GeneralSecurityException, IOException{
		return decryptDataWithSecretKey(encryptedData,recieverStore).getData();
	}
	
	/**
	 * Method to sign and then encrypt a Ieee1609Dot2Data structure.
	 * 
	 * @param hi the header information data to include.
	 * @param message the data to sign and encrypt
	 * @param signerIdentifierType signerIdentifierType type of signer identifier to include, one of SignerIdentifierType
	 * @param signerCertificateChain the complete chain up to the trust anchor. Important the trust anchor MUST be an explicit certificate and the array
	 * must be in the order of end entity certificate at position 0 and trust anchor last in array.
	 * @param signerPrivateKey  private key of signer.
	 * @param encAlg algorithm indicating which symmetric and depending on encryption method which asymmetric algorithm to use.
	 * @param recipients  a list of recipients, all receiptients should be a Recipient implementation and be of the same type.
	 * @return a signed and then encrypted Ieee1609Dot2Data structure.
	 * 
	 * @throws IllegalArgumentException if fault was discovered in supplied parameters.
	 * @throws SignatureException if internal problems occurred generating the signature.
	 * @throws IOException if IO exception occurred communicating with underlying systems. 
	 * @throws GeneralSecurityException if internal problems occurred encrypting the data.
	 */
	public EncryptResult signAndEncryptData(HeaderInfo hi, byte[] message, SignerIdentifierType signerIdentifierType, Certificate[] signerCertificateChain, PrivateKey signerPrivateKey, AlgorithmIndicator encAlg,Recipient[] recipients) throws IllegalArgumentException, SignatureException, GeneralSecurityException, IOException{
		return encryptData(encAlg, genSignedData(hi, message, signerIdentifierType, signerCertificateChain, signerPrivateKey).getEncoded(), recipients);
	}

	/**
	 * Method to self sign and then encrypt a Ieee1609Dot2Data structure.
	 *
	 * @param hi the header information data to include.
	 * @param message the data to sign and encrypt
	 * @param signerPublicKey the public key of the signer.
	 * @param signerPrivateKey  private key of signer.
	 * @param encAlg algorithm indicating which symmetric and depending on encryption method which asymmetric algorithm to use.
	 * @param recipients  a list of recipients, all receiptients should be a Recipient implementation and be of the same type.
	 * @return a signed and then encrypted Ieee1609Dot2Data structure.
	 *
	 * @throws IllegalArgumentException if fault was discovered in supplied parameters.
	 * @throws SignatureException if internal problems occurred generating the signature.
	 * @throws IOException if IO exception occurred communicating with underlying systems.
	 * @throws GeneralSecurityException if internal problems occurred encrypting the data.
	 */
	public EncryptResult selfSignAndEncryptData(HeaderInfo hi, byte[] message, PublicKey signerPublicKey, PrivateKey signerPrivateKey, AlgorithmIndicator encAlg,Recipient[] recipients) throws IllegalArgumentException, SignatureException, GeneralSecurityException, IOException{
		return encryptData(encAlg, genSignedData(hi, message, signerPublicKey, signerPrivateKey).getEncoded(), recipients);
	}

	/**
	 * Method to decrypt and verify a signed data structure, the method returns the SignedData object containing
	 * a unsecured payload. This method only verifies the signature and does not check other header info parameters.
	 * 
	 * @param message the message to decrypt and verify.
	 * @param certStore a list of known certificates that can be used to build a certificate path (excluding trust anchors).
     * @param trustStore certificates in trust store, must be explicit certificate in order to qualify as trust anchors.
	 * @param recieverStore the store of known receiver keys.
	 * @param requiredSignature if it should be required that messages are signed.
	 * @param requireEncryption if it should be required that message are encrypted.
	 * @return the decrypted data payload in the innermost unsecured data.
	 * @throws IllegalArgumentException if fault was discovered in supplied parameters.
	 * @throws GeneralSecurityException if internal problems occurred decrypting and verying the message.
	 * @throws IOException if IO exception occurred communicating with underlying systems.
	 */
	public DecryptAndVerifyResult decryptAndVerifySignedData(byte[] message, Map<HashedId8, Certificate> certStore, Map<HashedId8, Certificate> trustStore, Map<HashedId8, Receiver> recieverStore, boolean requiredSignature, boolean requireEncryption) throws IllegalArgumentException, GeneralSecurityException, IOException{
		HeaderInfo headerInfo = null;
		SignerIdentifier signerIdentifier = null;

		Ieee1609Dot2Data data = newEncryptedDataStructure(message);
		SecretKey secretKey = null;
		if(data.getContent().getType() == Ieee1609Dot2ContentChoices.encryptedData){
			DecryptResult decryptResult = decryptDataWithSecretKey(data, recieverStore);
			data = new Ieee1609Dot2Data(decryptResult.getData());
			secretKey = decryptResult.getSecretKey();
		}else{
			if(requireEncryption){
				throw new IllegalArgumentException("Invalid Ieee1609Dot2Data, must be encrypted.");
			}
		}
		
		if(data.getContent().getType() == Ieee1609Dot2ContentChoices.signedData || data.getContent().getType() == Ieee1609Dot2ContentChoices.signedCertificateRequest){
			if(!verifySignedData(data, certStore, trustStore)){
				throw new SignatureException("Error signature didn't verify");
			}
			SignedData signedData = (SignedData) data.getContent().getValue();
			data = signedData.getTbsData().getPayload().getData();
			headerInfo = signedData.getTbsData().getHeaderInfo();
			signerIdentifier = signedData.getSigner();
		}else{
			if(requiredSignature){
				throw new IllegalArgumentException("Invalid Ieee1609Dot2Data, must be signed.");
			}
		}
		
		if(data.getContent().getType() != Ieee1609Dot2ContentChoices.unsecuredData){
			throw new IllegalArgumentException("Invalid Ieee1609Dot2Data, signed payload content must be a unsecured data");
		}
		
		return new DecryptAndVerifyResult(signerIdentifier,headerInfo,secretKey,((Opaque) data.getContent().getValue()).getData());
	}

	/**
	 * Method to decrypt and verify a self signed signed data structure, the method returns the SignedData object containing
	 * a unsecured payload. This method only verifies the signature and does not check other header info parameters.
	 *
	 * @param message the message to decrypt and verify.
	 * @param signerPublicKey the signers public key used to verify the signature.
	 * @param recieverStore the store of known receiver keys.
	 * @param requiredSignature if it should be required that messages are signed.
	 * @param requireEncryption if it should be required that message are encrypted.
	 * @return the decrypted data payload in the innermost unsecured data.
	 * @throws IllegalArgumentException if fault was discovered in supplied parameters.
	 * @throws GeneralSecurityException if internal problems occurred decrypting and verying the message.
	 * @throws IOException if IO exception occurred communicating with underlying systems.
	 */
	public DecryptAndVerifyResult decryptAndVerifySelfSignedData(byte[] message, PublicKey signerPublicKey, Map<HashedId8, Receiver> recieverStore, boolean requiredSignature, boolean requireEncryption) throws IllegalArgumentException, GeneralSecurityException, IOException{
		HeaderInfo headerInfo = null;
		SignerIdentifier signerIdentifier = null;

		Ieee1609Dot2Data data = newEncryptedDataStructure(message);
		SecretKey secretKey = null;
		if(data.getContent().getType() == Ieee1609Dot2ContentChoices.encryptedData){
			DecryptResult decryptResult = decryptDataWithSecretKey(data, recieverStore);
			data = new Ieee1609Dot2Data(decryptResult.getData());
			secretKey = decryptResult.getSecretKey();
		}else{
			if(requireEncryption){
				throw new IllegalArgumentException("Invalid Ieee1609Dot2Data, must be encrypted.");
			}
		}

		if(data.getContent().getType() == Ieee1609Dot2ContentChoices.signedData || data.getContent().getType() == Ieee1609Dot2ContentChoices.signedCertificateRequest){
			if(!verifySignedData(data, signerPublicKey)){
				throw new SignatureException("Error signature didn't verify");
			}
			SignedData signedData = (SignedData) data.getContent().getValue();
			data = signedData.getTbsData().getPayload().getData();
			headerInfo = signedData.getTbsData().getHeaderInfo();
			signerIdentifier = signedData.getSigner();
		}else{
			if(requiredSignature){
				throw new IllegalArgumentException("Invalid Ieee1609Dot2Data, must be signed.");
			}
		}

		if(data.getContent().getType() != Ieee1609Dot2ContentChoices.unsecuredData){
			throw new IllegalArgumentException("Invalid Ieee1609Dot2Data, signed payload content must be a unsecured data");
		}

		return new DecryptAndVerifyResult(signerIdentifier,headerInfo,secretKey,((Opaque) data.getContent().getValue()).getData());
	}

	protected Ieee1609Dot2Data newEncryptedDataStructure(byte[] encodedData) throws IOException {
		return new Ieee1609Dot2Data(encodedData);
	}

	protected Ieee1609Dot2Data newEncryptedDataStructure(int version, Ieee1609Dot2Content content) throws IOException {
		return new Ieee1609Dot2Data(version,content);
	}

	/**
	 * Help method to generate a SecuredData Header Info without the need to build all required data structures.
	 * 
	 * @param psid the psid to set Required.
	 * @param generationTime the generation time as Date, Optional.
	 * @param expiryTime the exprity time as Date, Optional
	 * @param generationLocation the generation location.
	 * @param p2pcdLearningRequest the p2pcdLearningRequest 3 bytes, Optional
	 * @param cracaid the cracaid usid in missing crl identifier, if set must also crlSeries be set, otherwise null
	 * @param crlSeries the crl series used in missing crl identifier, Optional.
	 * @param encType the type of encryption used. if set must also encryption key be set, Optional
	 * @param encryptionKey the encryption key to set.
	 * @param inlineP2pcdRequest if present, is used by the SDS to request unknown certificates per the
	 * inline peer-to-peer certificate distribution mechanism is given in Clause 8. This field shall only be
	 * present if p2pcdLearningRequest is not present. The HashedId3 is calculated with the whole certificate
	 * hash algorithm, determined as described in 6.4.3.
	 * @param requestedCertificate if present, is used by the SDS to provide certificates per the "inline"
	 * version of the peer-to-peer certificate distribution mechanism.
	 * @return a generated header info structure.
	 * @throws IllegalArgumentException if supplied arguments where invalid.
	 * @throws InvalidKeySpecException if public key conversion failed.
	 */
	public HeaderInfo genHeaderInfo(long psid, Date generationTime, Date expiryTime, ThreeDLocation generationLocation,
									byte[] p2pcdLearningRequest, byte[] cracaid, Integer crlSeries, BasePublicEncryptionKeyChoices encType, PublicKey encryptionKey,
									SequenceOfHashedId3 inlineP2pcdRequest, Certificate requestedCertificate) throws IllegalArgumentException, InvalidKeySpecException{
		
		MissingCrlIdentifier mci = null;
		if(cracaid != null || crlSeries != null){
			if(cracaid != null && crlSeries  != null){
				mci = new MissingCrlIdentifier(new HashedId3(cracaid), new CrlSeries(crlSeries));
			}else{
				throw new IllegalArgumentException("Invalid argument building HeaderInfo, either must both cracaid and crlSeries be null or both set.");
			}
		}
		EncryptionKey encKey = null;
		if(encType != null || encryptionKey != null){
			if(encType != null && encryptionKey  != null){
				EccP256CurvePoint point = cryptoManager.encodeEccPoint(encType, EccP256CurvePointChoices.compressedy0, encryptionKey);
				encKey = new EncryptionKey(new PublicEncryptionKey(SymmAlgorithm.aes128Ccm, new BasePublicEncryptionKey(encType, point)));
			}else{
				throw new IllegalArgumentException("Invalid argument building HeaderInfo, either must both encType and encryptionKey be null or both set.");
			}
		}
		
		return new HeaderInfo(new Psid(psid), 
				(generationTime != null ? new Time64(generationTime) : null),  
				(expiryTime != null ? new Time64(expiryTime) : null),
				generationLocation,
				(p2pcdLearningRequest != null ? new HashedId3(p2pcdLearningRequest) : null), 
				mci, 
				encKey, inlineP2pcdRequest, requestedCertificate);
	}

	protected HashedId8 getReference(RecipientInfo ri) {
		switch (ri.getType()) {
		case pskRecipInfo:
			return (PreSharedKeyRecipientInfo) ri.getValue();
		case symmRecipInfo:
			SymmRecipientInfo sri = (SymmRecipientInfo) ri.getValue();
			return sri.getRecipientId();
		case certRecipInfo:
		case signedDataRecipInfo:
		case rekRecipInfo:
			PKRecipientInfo pri = (PKRecipientInfo) ri.getValue();
			return pri.getRecipientId();
		default:
		}
		throw new IllegalArgumentException("Unknown RecipientInfo type: " + ri.getType());
	}

	/**
	 * Help method to check if any recipient infos has a matching symmetric key in knownSymmetricKeys store.
	 * If it exists it decrypts the enveloped symmetric key and returns encrypted decryption key. 
	 */
	protected SecretKey getSymmetricKey(RecipientInfo[] recipientInfos,
			Map<HashedId8, SecretKey> knownSymmetricKeys) throws IllegalArgumentException, GeneralSecurityException {
		if(knownSymmetricKeys == null){
			return null;
		}
		for(RecipientInfo ri : recipientInfos){
			if(ri.getType() == RecipientInfoChoices.symmRecipInfo){
				SymmRecipientInfo sri = (SymmRecipientInfo) ri.getValue();
				SecretKey knownKey = knownSymmetricKeys.get(sri.getRecipientId());
				if(knownKey != null){
					// Decrypt the decryption key.
					SymmetricCiphertext symmetricCiphertext = sri.getEncKey();
					byte[] keyData = cryptoManager.symmetricDecryptIEEE1609_2_2017(symmetricCiphertext.getType(), getEncryptedData(symmetricCiphertext), knownKey.getEncoded(), getNounce(symmetricCiphertext));
					return cryptoManager.constructSecretKey(symmetricCiphertext.getType(), keyData);
				}
			}
		}
		return null;
	}

   public static byte[] getEncryptedData(SymmetricCiphertext symmetricCiphertext) {
		switch (symmetricCiphertext.getType()) {
		default:
		case aes128ccm:
			AesCcmCiphertext aesCcmCiphertext = (AesCcmCiphertext) symmetricCiphertext.getValue();
			return aesCcmCiphertext.getCcmCipherText();
		}
	}
	
	public static byte[] getNounce(SymmetricCiphertext symmetricCiphertext) {
		switch (symmetricCiphertext.getType()) {
		default:
		case aes128ccm:
			AesCcmCiphertext aesCcmCiphertext = (AesCcmCiphertext) symmetricCiphertext.getValue();
			return aesCcmCiphertext.getNounce();
		}
	}

	protected HashedId8 getPresharedKeyId(RecipientInfo[] recipientInfos) {
		if(recipientInfos.length > 0 && recipientInfos[0].getType() == RecipientInfoChoices.pskRecipInfo){
			return ((PreSharedKeyRecipientInfo) recipientInfos[0].getValue());
		}
		return null;
	}


	/**
	 * Help method to get a HashedId8 cert id from a SignerIdentifier.
	 */
	protected HashedId8 getSignerId(SignerIdentifier signer) throws IllegalArgumentException, NoSuchAlgorithmException, IOException {
		if(signer.getType() == SignerIdentifierChoices.digest){
			return (HashedId8) signer.getValue();
		}
		if(signer.getType() == SignerIdentifierChoices.self){
			throw new IllegalArgumentException("SignedData cannot be self signed");
		}
		SequenceOfCertificate sc = (SequenceOfCertificate) signer.getValue();
		return certChainBuilder.getCertID((Certificate) sc.getSequenceValues()[0]);
	}
	
	
	/**
	 * Builds a cert store if signer identifier contains included certificates, otherwise an empty map.
	 */
	public Map<HashedId8, Certificate> getSignedDataStore(SignerIdentifier signer) throws IllegalArgumentException, NoSuchAlgorithmException, IOException {
		if(signer.getType() != SignerIdentifierChoices.certificate){
			return new HashMap<HashedId8, Certificate>();
		}
		COEREncodable[] certs = ((SequenceOfCertificate) signer.getValue()).getSequenceValues();
		return buildCertStore(Arrays.copyOf(certs,certs.length, Certificate[].class));
	}
	

	/**
	 * Help method that generated a HashedId8 secret key id from a symmetric key.
	 */
	protected HashedId8 getSecretKeyID(AlgorithmIndicator alg,SecretKey key) throws IllegalArgumentException, NoSuchAlgorithmException, IOException{
		SymmetricEncryptionKey symmetricEncryptionKey = new SymmetricEncryptionKey(SymmetricEncryptionKey.SymmetricEncryptionKeyChoices.getChoiceFromAlgorithm(alg),key.getEncoded());
		return new HashedId8(cryptoManager.digest(symmetricEncryptionKey.getEncoded(), hashAlgorithm));
	}
	
	protected Ieee1609Dot2Data genSignedDataStructure(ToBeSignedData tbsData,  SignerIdentifierType signerIdentifierType, Certificate[] signerCertificateChain, PublicKey signerPublicKey, PrivateKey signerPrivateKey, boolean enveloped) throws IllegalArgumentException, InvalidKeySpecException, SignatureException, IOException, NoSuchAlgorithmException{
		SignerIdentifier si;
		Certificate signingCert = null;
		CertificateType certificateType = CertificateType.explicit;
		if(signerIdentifierType != SignerIdentifierType.SELF) {
			si = getSignerIdentifier(signerIdentifierType, signerCertificateChain);
			signingCert = signerCertificateChain[0];
			certificateType = signingCert.getType();
		}else{
			si = new SignerIdentifier();
		}
		Signature signature = cryptoManager.signMessage(tbsData.getEncoded(), signAlgorithm,  signerPrivateKey, certificateType, signingCert);

		SignedData signedData = new SignedData(hashAlgorithm, tbsData, si, signature);

		Ieee1609Dot2Content content = new Ieee1609Dot2Content(signedData);
		Ieee1609Dot2Data retval = newSignedDataStructure(version,content, enveloped);
		
		return retval;
	}

	/**
	 * Overridable method that creates a new signed Ieee1609Dot2Data structure
	 *
	 * @param version version of message.
	 * @param content the data content.
	 * @param enveloped if signature data is included or external reference is used.
	 */
	protected Ieee1609Dot2Data newSignedDataStructure(int version, Ieee1609Dot2Content content, boolean enveloped){
		return new Ieee1609Dot2Data(version,content);
	}

	/**
	 * 
	 * @return the related HashDataChoice used in referenced signed data.
	 */
	protected HashedDataChoices getHashedDataChoice() {
		switch (hashAlgorithm) {
		default:
			return HashedDataChoices.sha256HashedData;
		}
	}
	/**
	 * Help method extracting the signers public key from the signer certificate chain.
	 */
	protected PublicKey getSignerPublicKey(Certificate[] signerCertificateChain) throws IllegalArgumentException, InvalidKeySpecException, SignatureException, IOException{
		Integer firstExplicitIndex = null;
		for(int i=0;i<signerCertificateChain.length; i++){
			if(signerCertificateChain[i].getType() == CertificateType.explicit){
				firstExplicitIndex = i;
				break;
			}
		}
		if(firstExplicitIndex == null){
			throw new IllegalArgumentException("Error no explicit certificate found in signer certificate chain");
		}
		
		int i = firstExplicitIndex;
		PublicVerificationKey  pubVerKey = (PublicVerificationKey) signerCertificateChain[i].getToBeSigned().getVerifyKeyIndicator().getValue();
		AlgorithmIndicator alg = pubVerKey.getType();
		PublicKey explicitPublicKey = (PublicKey) cryptoManager.decodeEccPoint(alg, (EccCurvePoint) pubVerKey.getValue());
		if(firstExplicitIndex == 0){
			return explicitPublicKey;
		}
		// Build public key backwards.
		PublicKey reconstructedKey = explicitPublicKey;
		while(i>0){
			i--;
			reconstructedKey = ecqvHelper.extractPublicKey(signerCertificateChain[i], (BCECPublicKey) reconstructedKey, alg, signerCertificateChain[i+1]);
		}
		
		
		return reconstructedKey;
	}
	
	/**
	 * Help method generating the signer identifier given one of the signer identifier type.
	 */
	protected SignerIdentifier getSignerIdentifier(
			SignerIdentifierType signerIdentifierType,
			Certificate[] signerCertificateChain) throws IllegalArgumentException, NoSuchAlgorithmException, IOException {
		Certificate signerCert = signerCertificateChain[0];
		switch (signerIdentifierType) {
			case SELF:
				return new SignerIdentifier();
			case HASH_ONLY:
				return new SignerIdentifier(new HashedId8(cryptoManager.digest(signerCert.getEncoded(), hashAlgorithm)));
			case SIGNER_CERTIFICATE:
				return new SignerIdentifier(new SequenceOfCertificate(new Certificate[]{signerCert}));
			case CERT_CHAIN:
			default:
				if(signerCertificateChain.length < 2){
					throw new IllegalArgumentException("Error invalid certificate chain length when creating signer identifier of type COMPLETE_CHAIN, chain length must be larger than 1");
				}
				Certificate[] certChain = new Certificate[signerCertificateChain.length-1];
				for(int i=0; i < certChain.length; i++){
					certChain[i] = signerCertificateChain[i];
				}
				return new SignerIdentifier(new SequenceOfCertificate(certChain));
		}
	}

	/**
	 *
	 * @return the underlying cryptoManger used in teh SecureDataGenerator.
	 */
	public Ieee1609Dot2CryptoManager getCryptoManager(){
		return cryptoManager;
	}


		
}
