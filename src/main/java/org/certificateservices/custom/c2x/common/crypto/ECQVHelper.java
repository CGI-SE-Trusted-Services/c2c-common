package org.certificateservices.custom.c2x.common.crypto;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.certificateservices.custom.c2x.asn1.coer.COERChoice;
import org.certificateservices.custom.c2x.common.BadArgumentException;
import org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EccCurvePoint;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EccP256CurvePoint;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EccP384CurvePoint;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.ToBeSignedCertificate;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.VerificationKeyIndicator;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.ImplicitCertificateData;

public class ECQVHelper {
	

	private Ieee1609Dot2CryptoManager cryptoManager = null;
	private static KeyFactory keyFact;

	static{
		try {
			keyFact = KeyFactory.getInstance("EC", "BC");
		} catch(Exception e) {
			throw new RuntimeException("Error occurred initializing ECQV algorithm: " + e.getMessage(), e);
		}
	}


	
	/**
	 * Initializes ECQV Helper with related crypto manager.
	 * @param cryptoManager the related crypto manager.
	 * 
	 * @throws SignatureException if problems occurred initializing internal key factory.
	 */
	public ECQVHelper(Ieee1609Dot2CryptoManager cryptoManager){
		this.cryptoManager = cryptoManager;
	}
	

	/**
	 * Method that generates and sets the reconstruction value and related private key r value in the implicit certificate data structure.
	 * <p>
	 * <b>Important: The r value is not a part of the certificate.</b>
	 * 
	 * @param implicitCertData the certificate data structure with rv set as placeholder only, replaced with actual value in this metod.
	 * @param alg related algorithm
	 * @param publicKey the public key from the certificate request and used as basis for the reconstruction value.
	 * @param signerCert the signing certificate (CA).
	 * @param signerPublicKey the signing certificate public key.
	 * @param signerPrivateKey the signing certificate private key.
	 * @return a newly generated implicit certificate data.
	 * @throws IOException if communication problems occurred with underlying systems.
	 * @throws BadArgumentException if argument was illegal
	 * @throws SignatureException if internal problems occurred generating the reconstruction value.
	 */
	public ImplicitCertificateData genImplicitCertificate(ImplicitCertificateData implicitCertData, AlgorithmIndicator alg, ECPublicKey publicKey, 
			Certificate signerCert,
			BCECPublicKey signerPublicKey,
			BCECPrivateKey signerPrivateKey) throws  IOException, BadArgumentException, SignatureException{

		try{
		ToBeSignedCertificate tbs = implicitCertData.getToBeSigned();
		ECParameterSpec domainParameters = cryptoManager.getECParameterSpec(alg);
		
		//  3.4 Action 1  Decode RU
		BCECPublicKey Ru =  cryptoManager.toBCECPublicKey(alg, publicKey);

		// 3.4 Action 2 Validate Ru
		validatePublicKey(Ru);

		ECPoint Pu = null;
		BigInteger e = null;
		KeyPair k_kG = null;
		byte[] certData = null;

		do{
			// 3.4 Action 3 Generate an EC key pair (k, kG)
			k_kG = cryptoManager.generateKeyPair(alg);

			// 3.4 Action 4 	Compute the elliptic curve point Pu = Ru + kG
			Pu = Ru.getQ().add(((BCECPublicKey) k_kG.getPublic()).getQ());

			// 3.4 Action 5 Convert Pu to the octet string PU
			EccCurvePoint PU;
			if(alg.getAlgorithm().getSignature() == Algorithm.Signature.ecdsaBrainpoolP384r1){
				PU =  new EccP384CurvePoint(Pu.getEncoded(true));
			}else{
				PU =  new EccP256CurvePoint(Pu.getEncoded(true));
			}
			
			// 3.4 Action 6 Create Certificate Structure
			// Create a reconstruction value
			VerificationKeyIndicator verificationKeyIndicator = new VerificationKeyIndicator(PU);
			tbs.setVerifyKeyIndicator(verificationKeyIndicator);
			
			certData = tbs.getEncoded();
			
			e = computeHash(cryptoManager,certData, alg, signerCert);

			// 3.4 Action 8 Check that e doesn't compute to infinity
		}while(Pu.multiply(e).add((signerPublicKey).getQ()).isInfinity());

		// 3.4 Action 9 Compute the integer r
		BigInteger k = ((BCECPrivateKey) k_kG.getPrivate()).getD();
		BigInteger r = k.multiply(e).add((signerPrivateKey).getD()).mod(domainParameters.getN());

		implicitCertData.setR(r);
		
		return implicitCertData;
		}catch(Exception e){
			if(e instanceof BadArgumentException){
				throw (BadArgumentException) e;
			}
			if(e instanceof IOException){
				throw (IOException) e;
			}
			throw new SignatureException("Error generating reconstruction value for implicit certificate: " + e.getMessage(),e);
		}
	}

	/**
	 * Method to extract a public key from a implicit certificate.
	 *
	 * @param cert the implicit certificate to reconstruct the public key for.
	 * @param caPublicKey the public key of the CA.
	 * @param alg the related algorithm used.
	 * @param signerCertificate the CA certificate public key.
	 * @return a generate EC Public Key.
	 *
	 * @throws IOException if communication problems occurred with underlying systems.
	 * @throws BadArgumentException if argument was illegal
	 * @throws SignatureException if internal problems occurred extracting the public key.
	 */
	public BCECPublicKey extractPublicKey(Certificate cert, BCECPublicKey caPublicKey, AlgorithmIndicator alg, Certificate signerCertificate) throws BadArgumentException, IOException, SignatureException{
		return extractPublicKey(cryptoManager, cert,caPublicKey,alg,signerCertificate);
	}

	/**
	 * Method to extract a public key from a implicit certificate.
	 * 
	 * @param cert the implicit certificate to reconstruct the public key for.
	 * @param caPublicKey the public key of the CA.
	 * @param alg the related algorithm used.
	 * @param signerCertificate the CA certificate public key.
	 * @return a generate EC Public Key.
	 * 
	 * @throws IOException if communication problems occurred with underlying systems.
	 * @throws BadArgumentException if argument was illegal
	 * @throws SignatureException if internal problems occurred extracting the public key.
	 */
	public static BCECPublicKey extractPublicKey(Ieee1609Dot2CryptoManager cryptoManager, Certificate cert, BCECPublicKey caPublicKey, AlgorithmIndicator alg, Certificate signerCertificate) throws BadArgumentException, IOException, SignatureException{
		try{
		ToBeSignedCertificate tbs = cert.getToBeSigned();
		ECParameterSpec domainParameters = cryptoManager.getECParameterSpec(alg);
		
		
		// Get public key from reconstruction value
		EccCurvePoint PU = (EccCurvePoint) tbs.getVerifyKeyIndicator().getValue();
		BCECPublicKey Pu = (BCECPublicKey) cryptoManager.decodeEccPoint(alg, PU);
		
		if(!Pu.getQ().isValid()){
			throw new InvalidKeyException("Error Public Key is invalid");
		}
		
		BigInteger e = computeHash(cryptoManager, tbs.getEncoded(), alg, signerCertificate);
		
		ECPoint Qu = Pu.getQ().multiply(e).add(caPublicKey.getQ());
		
		ECPublicKeySpec spec = new ECPublicKeySpec(Qu, domainParameters);
		
		BCECPublicKey retval =  (BCECPublicKey) keyFact.generatePublic(spec);
		
		return retval;
		}catch(Exception e){
			if(e instanceof BadArgumentException){
				throw (BadArgumentException) e;
			}
			if(e instanceof IOException){
				throw (IOException) e;
			}
			throw new SignatureException("Error extracting public key for implicit certificate: " + e.getMessage(),e);
		}
	}

	/**
	 * Method to construct the private key related to a generate certificate, given the related r value.
	 * 
	 * @param cert the generated certificate.
	 * @param r the private key r value
	 * @param alg the related algorithm
	 * @param Ku the private key generate for the certificate request.
	 * @param signerPublicKey the CA public key.
	 * @param signerCertificate the CA certificate
	 * @return a generated private key.
	 * @throws IOException if communication problems occurred with underlying systems.
	 * @throws BadArgumentException if argument was illegal
	 * @throws SignatureException if internal problems occurred constructing the certificate private key.
	 */
	public ECPrivateKey certReceiption(Certificate cert, BigInteger r, AlgorithmIndicator alg, ECPrivateKey Ku, ECPublicKey signerPublicKey, Certificate signerCertificate) throws IOException, BadArgumentException, SignatureException{
		try{
			ToBeSignedCertificate tbs = cert.getToBeSigned();
			BCECPublicKey caPublicKey = cryptoManager.toBCECPublicKey(alg, signerPublicKey);
			ECParameterSpec domainParameters = cryptoManager.getECParameterSpec(alg);

			// Convert to BCPrivateKey

			BCECPublicKey Qu = extractPublicKey(cert, caPublicKey, alg, signerCertificate);

			BigInteger e = computeHash(cryptoManager,tbs.getEncoded(), alg, signerCertificate);

			// TODO start with bc key, then try with domainParameter.d
			BigInteger Du = r.add(e.multiply(((BCECPrivateKey) Ku).getD())).mod(domainParameters.getN());

			if(!Qu.getQ().equals(domainParameters.getG().multiply(Du))){
				throw new InvalidKeyException("Invalid private key received");
			}

			ECPrivateKeySpec privateKeySpec = new ECPrivateKeySpec(Du, domainParameters);
			ECPrivateKey privateKey = (ECPrivateKey) keyFact.generatePrivate(privateKeySpec);
			return privateKey;

		}catch(Exception e){
			if(e instanceof BadArgumentException){
				throw (BadArgumentException) e;
			}
			if(e instanceof IOException){
				throw (IOException) e;
			}
			throw new SignatureException("Error extracting public key for implicit certificate: " + e.getMessage(),e);
		}
	}
		

	/**
	 * Help method to compute the hash integer value according to ECQV SEC 4 Specification.
	 */
	private static BigInteger computeHash(Ieee1609Dot2CryptoManager cryptoManager, byte[] certData, AlgorithmIndicator alg, Certificate signerCertificate) throws BadArgumentException, NoSuchAlgorithmException, IOException {
		ECParameterSpec domainParameters = cryptoManager.getECParameterSpec(alg);
		
		
		byte[] h = cryptoManager.genIEEECertificateDigest(alg,certData, signerCertificate);
		int fieldSize = domainParameters.getCurve().getFieldSize()/8;
		byte[] E = new byte[fieldSize];
		ByteBuffer bb = ByteBuffer.wrap(E);
		if(h.length > fieldSize ){
			bb.put(h,0,fieldSize);
		}else{
			bb.put(h, fieldSize - h.length, h.length);
		}
		
		return new BigInteger(1, E);
	}


	/**
	 * Help method to validate a public key.
	 */
	private void validatePublicKey(BCECPublicKey pk) throws InvalidKeyException{
		if(!pk.getQ().isValid()){
			throw new InvalidKeyException("Error EC public key was invalid.");
		}
	}
	




}
