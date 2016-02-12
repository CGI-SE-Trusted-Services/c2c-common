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

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.certificateservices.custom.c2x.asn1.coer.COEROctetStream;
import org.certificateservices.custom.c2x.common.crypto.AlgorithmIndicator;
import org.certificateservices.custom.c2x.common.crypto.ECQVHelper;
import org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EccP256CurvePoint;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashAlgorithm;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId8;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Opaque;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PublicVerificationKey;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature.SignatureChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.CertificateType;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.SequenceOfCertificate;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.IssuerIdentifier.IssuerIdentifierChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.HashedData;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.HashedData.HashedDataChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.HeaderInfo;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.Ieee1609Dot2Content;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.Ieee1609Dot2Content.Ieee1609Dot2ContentChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.Ieee1609Dot2Data;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.SignedData;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.SignedDataPayload;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.SignerIdentifier;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.SignerIdentifier.SignerIdentifierChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.ToBeSignedData;


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
		CERT_CHAIN;
	}

	Ieee1609Dot2CryptoManager cryptoManager = null;
	boolean useUncompressed = false;
	int version = Ieee1609Dot2Data.DEFAULT_VERSION;
	HashAlgorithm hashAlgorithm;
	ECQVHelper ecqvHelper;	
	SignatureChoices signAlgorithm;

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
		
		try{
			Ieee1609Dot2Data unsecuredData = new Ieee1609Dot2Data(version,new Ieee1609Dot2Content(Ieee1609Dot2ContentChoices.unsecuredData, new Opaque(message)));
			ToBeSignedData tbsData = new ToBeSignedData(new SignedDataPayload(unsecuredData, null), hi);

			return genSignedDataStructure(tbsData, signerIdentifierType, signerCertificateChain, signerPrivateKey);
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

			return genSignedDataStructure(tbsData, signerIdentifierType, signerCertificateChain, signerPrivateKey);
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
			retval.put(new HashedId8(cryptoManager.digest(cert.getEncoded(), hashAlgorithm)), cert);
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
			Certificate[] signerCertChain = buildChain(signerId, signedDataStore, certStore, trustStore);
			PublicKey signerPublicKey = getSignerPublicKey(signerCertChain);
			return cryptoManager.verifySignature(sd.getTbsData().getEncoded(), sd.getSignature(), signerCertChain[0], signerPublicKey);
		}catch(NoSuchAlgorithmException e){
			throw new SignatureException("Error verifying message, no such algorithm found when verifing signed data: " + e.getMessage(),e);
		} catch (InvalidKeySpecException e) {
			throw new IllegalArgumentException("Error verifying message, invalid key spec: " + e.getMessage(),e);
		}
	}
	
    /**
     * Method to verify a signed data, method only verifies the signature, it doesn't validate it by permissions, validity or geographically.
     * @param signedData the signed data to verify.
     * @param referenceData the signature refers to.
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
			Certificate[] signerCertChain = buildChain(signerId, signedDataStore, certStore, trustStore);
			PublicKey signerPublicKey = getSignerPublicKey(signerCertChain);
			return cryptoManager.verifySignature(sd.getTbsData().getEncoded(), sd.getSignature(), signerCertChain[0], signerPublicKey);
		}catch(NoSuchAlgorithmException e){
			throw new SignatureException("Error verifying message, no such algorithm found when verifing signed data: " + e.getMessage(),e);
		} catch (InvalidKeySpecException e) {
			throw new IllegalArgumentException("Error verifying message, invalid key spec: " + e.getMessage(),e);
		}
	}
	

	/**
	 * Help method to build a certificate chain from a signerId and two collections of known certificates and trust store.
	 * 
	 * @throws IllegalArgumentException if chain couldn't be built.
	 */
	protected Certificate[] buildChain(HashedId8 signerId, Map<HashedId8, Certificate> signedDataStore, Map<HashedId8, Certificate> certStore, Map<HashedId8, Certificate> trustStore) throws IllegalArgumentException, NoSuchAlgorithmException, IOException{
		List<Certificate> foundCerts = new ArrayList<Certificate>();
		// find first cert
		Certificate firstCert=null;
		firstCert = findFromStores(signerId, signedDataStore, certStore, trustStore);
	
		if(firstCert == null){
			throw new IllegalArgumentException("Error no cerificate found in certstore for id : " + signerId);
		}
		foundCerts.add(firstCert);
		Certificate nextCert = firstCert;
		while(nextCert.getIssuer().getType() != IssuerIdentifierChoices.self){
			HashedId8 issuerId = (HashedId8) nextCert.getIssuer().getValue();
			nextCert = findFromStores(issuerId, signedDataStore, certStore, trustStore);
			if(nextCert == null){
				throw new IllegalArgumentException("Error no cerificate found in certstore for id : " + signerId);
			}
			foundCerts.add(nextCert);
		}
		
		HashedId8 trustAncor = getCertID(foundCerts.get(foundCerts.size() -1));
		if(trustStore.get(trustAncor) == null){
			throw new IllegalArgumentException("Error last certificate in chain wasn't a trust anchor: " + trustAncor);
		}
		
		return foundCerts.toArray(new Certificate[foundCerts.size()]);
	}
	

	/**
	 * Help method that tries to first find the certificate from cert store and then in trust store if not found.
	 * It also checks that trust store certificate is an explicit certificate.
	 * @return the found certificate or null if no certificate found in any of the stores.
	 * @throws if found an implicit certificate in trust store.
	 */
	protected Certificate findFromStores(HashedId8 certId, Map<HashedId8, Certificate> signedDataStore, Map<HashedId8, Certificate> certStore, Map<HashedId8, Certificate> trustStore) throws IllegalArgumentException{
		Certificate retval = signedDataStore.get(certId);
		if(retval != null){
			return retval;
		}
		
		retval = certStore.get(certId);
		if(retval != null){
			return retval;
		}
		
		retval = trustStore.get(certId);
		if(retval != null && retval.getType() == CertificateType.implicit){
			throw new IllegalArgumentException("Error trust ancor cannot be an implicit certificate");
		}
		return retval;
		
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
		return getCertID((Certificate) sc.getSequenceValues()[0]);
	}
	
	
	/**
	 * Builds a cert store if signer identifier contains included certificates, otherwise an empty map.
	 */
	private Map<HashedId8, Certificate> getSignedDataStore(SignerIdentifier signer) throws IllegalArgumentException, NoSuchAlgorithmException, IOException {
		if(signer.getType() != SignerIdentifierChoices.certificate){
			return new HashMap<HashedId8, Certificate>();
		}
		
		return buildCertStore((Certificate[]) ((SequenceOfCertificate) signer.getValue()).getSequenceValues());
	}
	
	/**
	 * Help method that generated a HashedId8 cert id from a certificate.
	 */
	protected HashedId8 getCertID(Certificate cert) throws IllegalArgumentException, NoSuchAlgorithmException, IOException{
		return new HashedId8(cryptoManager.digest(cert.getEncoded(), hashAlgorithm));
	}

	protected Ieee1609Dot2Data genSignedDataStructure(ToBeSignedData tbsData,  SignerIdentifierType signerIdentifierType, Certificate[] signerCertificateChain, PrivateKey signerPrivateKey) throws IllegalArgumentException, InvalidKeySpecException, SignatureException, IOException, NoSuchAlgorithmException{
		PublicKey signerPublicKey = getSignerPublicKey(signerCertificateChain);
		SignerIdentifier si = getSignerIdentifier(signerIdentifierType, signerCertificateChain);
		Certificate signingCert = signerCertificateChain[0];
		Signature signature = cryptoManager.signMessage(tbsData.getEncoded(), signAlgorithm, signerPublicKey, signerPrivateKey, signingCert.getType(), signingCert);

		SignedData signedData = new SignedData(hashAlgorithm, tbsData, si, signature);

		Ieee1609Dot2Content content = new Ieee1609Dot2Content(signedData);
		Ieee1609Dot2Data retval = new Ieee1609Dot2Data(version,content);
		
		return retval;
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
		PublicKey explicitPublicKey = (PublicKey) cryptoManager.decodeEccPoint(alg, (EccP256CurvePoint) pubVerKey.getValue());
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

	

	

		
}
