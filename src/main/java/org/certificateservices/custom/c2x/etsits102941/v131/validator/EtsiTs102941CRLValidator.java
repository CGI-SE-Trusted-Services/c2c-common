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
package org.certificateservices.custom.c2x.etsits102941.v131.validator;

import org.certificateservices.custom.c2x.common.BadArgumentException;
import org.certificateservices.custom.c2x.common.CertStore;
import org.certificateservices.custom.c2x.common.validator.CRLValidator;
import org.certificateservices.custom.c2x.common.validator.CertificateRevokedException;
import org.certificateservices.custom.c2x.common.validator.InvalidCRLException;
import org.certificateservices.custom.c2x.common.validator.InvalidCertificateException;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist.EtsiTs102941CRL;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist.ToBeSignedCrl;
import org.certificateservices.custom.c2x.etsits102941.v131.util.Etsi102941CRLHelper;
import org.certificateservices.custom.c2x.etsits103097.v131.validator.CRLServicePermissions;
import org.certificateservices.custom.c2x.etsits103097.v131.validator.ETSI103097CertificateValidator;
import org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.GeographicRegion;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId8;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.EndEntityType;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.SignerIdentifier;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.CertChainBuilder;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.SecuredDataGenerator;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.Date;
import java.util.Map;

/**
 * EtsiTs102941CRLValidator contains method to verify and validate a CRL and check if a given certificate
 * is revoked.
 *
 * @author Philip Vendil 2020-02-04
 */
public class EtsiTs102941CRLValidator extends BaseEtsiTs102941ListValidator implements CRLValidator  {

    protected SecuredDataGenerator securedDataGenerator;
    protected ETSI103097CertificateValidator certificateValidator;
    protected Etsi102941CRLHelper etsi102941CRLHelper = new Etsi102941CRLHelper();

    /**
     * Constructor of CRL validator class.
     *
     * @param cryptoManager the crypto manager used.
     * @param securedDataGenerator the secured data generator used.
     * @param certificateValidator the certificate validator used.
     */
    public EtsiTs102941CRLValidator(Ieee1609Dot2CryptoManager cryptoManager, SecuredDataGenerator securedDataGenerator,
                                    ETSI103097CertificateValidator certificateValidator){
        super(cryptoManager);
        this.securedDataGenerator = securedDataGenerator;
        this.certificateValidator = certificateValidator;
    }
    /**
     * Method that verifies and validates a CRL and checks if related certificate is revoked.
     * <p>
     * <i>Important</i>The method will only verify the CRL and to the specified certificate,
     * it should be validated separately.
     * </p>
     * <p>
     * The method will build a chain for the CRL from the set of trust anchors.
     * </p>
     * <p>
     * <p>
     * For each CRL in the built chain it will check.
     * <ul>
     * <li>Signature verifies</li>
     * <li>CRL validity</li>
     * <li>Issuing Certificate has permissions to issue CRLs</li>
     * <li>That specified certificate isn't included.</li>
     * </ul>
     * <p>
     * <b>Permissions is only checked that it is consistent upwards in the chain. It does not check a specific permission</b>
     * </p>
     *
     * @param crl         the CRL to verify, validate and check if specified certificate is revoked.
     * @param certificate the certificate check if revoked. If null is revocation not checked.
     * @param checkDate   the date to check validity of CRL and its certificate chain against.
     * @param checkRegion the region to check against, if null is region check skipped.
     * @param trustStore  a certstore of root ca certificates that are trusted.
     * @param entireChain if entireChain should be validated or only CRL.
     * @throws BadArgumentException    if one of the parameters where invalid.
     * @throws InvalidCRLException if CRL was not verifiable or not within time constraints.
     * @throws InvalidCertificateException if one of the certificate in the build certificate chain was invalid.
     * @throws NoSuchAlgorithmException    if use hash algorithm isn't supported by the system.
     * @throws CertificateRevokedException if related certificate was revoked.
     */
    @Override
    public void verifyAndValidate(EtsiTs102941CRL crl, Certificate certificate, Date checkDate, GeographicRegion checkRegion, CertStore trustStore, boolean entireChain)
            throws BadArgumentException, InvalidCRLException, InvalidCertificateException, NoSuchAlgorithmException, CertificateRevokedException {

        verifyAndValidate(crl, certificate != null ? toHashedId8(certificate) : null, checkDate, checkRegion, null, trustStore, entireChain);
    }

    /**
     * Method that verifies and validates a CRL and checks if related certificate is revoked.
     * <p>
     * <i>Important</i>The method will only verify the CRL and to the specified certificate,
     * it should be validated separately.
     * </p>
     * <p>
     * The method will build a chain for the CRL from the set of trust anchors.
     * </p>
     * <p>
     * <p>
     * For each CRL in the built chain it will check.
     * <ul>
     * <li>Signature verifies</li>
     * <li>CRL validity</li>
     * <li>Issuing Certificate has permissions to issue CRLs</li>
     * <li>That specified certificate isn't included.</li>
     * </ul>
     * <p>
     * <b>Permissions is only checked that it is consistent upwards in the chain. It does not check a specific permission</b>
     * </p>
     *
     * @param crl           the CRL to verify, validate and check if specified certificate is revoked.
     * @param certificateId the certificate id to check if revoked. If null is revocation not checked.
     * @param checkDate     the date to check validity of CRL and its certificate chain against.
     * @param checkRegion the region to check against, if null is region check skipped.
     * @param trustStore    a certstore of root ca certificates that are trusted.
     * @param entireChain   if entireChain should be validated or only CRL.
     * @throws BadArgumentException    if one of the parameters where invalid.
     * @throws InvalidCRLException if CRL was not verifyable or not within time constraints.
     * @throws InvalidCertificateException if one of the certificate in the build certificate chain was invalid.
     * @throws NoSuchAlgorithmException    if use hash algorithm isn't supported by the system.
     * @throws CertificateRevokedException if related certificate was revoked.
     */
    @Override
    public void verifyAndValidate(EtsiTs102941CRL crl, HashedId8 certificateId, Date checkDate, GeographicRegion checkRegion,
                                  CertStore trustStore, boolean entireChain)
            throws BadArgumentException, InvalidCRLException, InvalidCertificateException, NoSuchAlgorithmException,
            CertificateRevokedException {
        verifyAndValidate(crl, certificateId, checkDate, checkRegion, null, trustStore, entireChain);
    }



    /**
     * Method that verifies and validates a CRL and checks if related certificate is revoked.
     * This method have support for a intermediate CAs between rootca and EA and AA.
     * <p>
     * <i>Important</i>The method will only verify the CRL and to the specified certificate,
     * it should be validated separately.
     * </p>
     * <p>
     * The method will build a chain for the CRL from the set of trust anchors.
     * </p>
     * <p>
     * <p>
     * For each CRL in the built chain it will check.
     * <ul>
     * <li>Signature verifies</li>
     * <li>CRL validity</li>
     * <li>Issuing Certificate has permissions to issue CRLs</li>
     * <li>That specified certificate isn't included.</li>
     * </ul>
     * <p>
     * <b>Permissions is only checked that it is consistent upwards in the chain. It does not check a specific permission</b>
     * </p>
     *
     * @param crl         the CRL to verify, validate and check if specified certificate is revoked.
     * @param certificate the certificate check if revoked. If null is revocation not checked.
     * @param checkDate   the date to check validity of CRL and its certificate chain against.
     * @param checkRegion the region to check against, if null is region check skipped.
     * @param certStore   a certstore that contains all intermediate CA certificates that is needed to build the chain.
     * @param trustStore  a certstore of root ca certificates that are trusted.
     * @param entireChain if entireChain should be validated or only first certificate in chain.
     * @throws BadArgumentException    if one of the parameters where invalid.
     * @throws InvalidCRLException if CRL was not verifyable or not within time constraints.
     * @throws InvalidCertificateException if one of the certificate in the build certificate chain was invalid.
     * @throws NoSuchAlgorithmException    if use hash algorithm isn't supported by the system.
     * @throws CertificateRevokedException if related certificate was revoked.
     */
    @Override
    public void verifyAndValidate(EtsiTs102941CRL crl, Certificate certificate, Date checkDate, GeographicRegion checkRegion,
                                  CertStore certStore, CertStore trustStore,
                                  boolean entireChain)
            throws BadArgumentException, InvalidCRLException, InvalidCertificateException, NoSuchAlgorithmException,
            CertificateRevokedException {
        verifyAndValidate(crl, certificate != null ? toHashedId8(certificate) : null, checkDate, checkRegion, certStore, trustStore, entireChain);
    }

    /**
     * Method that verifies and validates a CRL and checks if related certificate id is revoked.
     * This method have support for a intermediate CAs between rootca and EA and AA.
     * <p>
     * <i>Important</i>The method will only verify the CRL and to the specified certificate,
     * it should be validated separately.
     * </p>
     * <p>
     * The method will build a chain for the CRL from the set of trust anchors.
     * </p>
     * <p>
     * <p>
     * For each CRL in the built chain it will check.
     * <ul>
     * <li>Signature verifies</li>
     * <li>CRL validity</li>
     * <li>Issuing Certificate has permissions to issue CRLs</li>
     * <li>That specified certificate isn't included.</li>
     * </ul>
     * <p>
     * <b>Permissions is only checked that it is consistent upwards in the chain. It does not check a specific permission</b>
     * </p>
     *
     * @param crl           the CRL to verify, validate and check if specified certificate is revoked.
     * @param certificateId the certificate id to check if revoked. If null is revocation not checked.
     * @param checkDate     the date to check validity of CRL and its certificate chain against.
     * @param checkRegion the region to check against, if null is region check skipped.
     * @param certStore     a certstore that contains all intermediate CA certificates that is needed to build the chain.
     * @param trustStore    a certstore of root ca certificates that are trusted.
     * @param entireChain   if entireChain should be validated or only first certificate in chain.
     * @throws BadArgumentException    if one of the parameters where invalid.
     * @throws InvalidCRLException if CRL was not verifyable or not within time constraints.
     * @throws InvalidCertificateException if one of the certificate in the build certificate chain was invalid.
     * @throws NoSuchAlgorithmException    if use hash algorithm isn't supported by the system.
     * @throws CertificateRevokedException if related certificate was revoked.
     */
    @Override
    public void verifyAndValidate(EtsiTs102941CRL crl, HashedId8 certificateId, Date checkDate, GeographicRegion checkRegion,
                                  CertStore certStore, CertStore trustStore,
                                  boolean entireChain) throws BadArgumentException, InvalidCRLException,
            InvalidCertificateException, NoSuchAlgorithmException, CertificateRevokedException {

        if(certStore == null){
            certStore = emptyStore;
        }
        try {
            if(!securedDataGenerator.verifySignedData(crl,certStore, trustStore)){
                throw new InvalidCRLException("Couldn't verify the CRL.");
            }
        } catch (SignatureException e) {
            throw new InvalidCRLException("Couldn't verify CRL signature: " + e.getMessage(),e);
        } catch (IOException e) {
            throw new InvalidCRLException("Couldn't decode CRL data: " + e.getMessage(),e);
        }catch(BadArgumentException e){
            throw new InvalidCRLException("RootCA not trusted: " + e.getMessage(),e);
        }

        try {
            SignerIdentifier signerIdentifier = findSignerIdentifier(crl);
            CertStore inCRLCertStore = SecuredDataGenerator.getSignedDataStore(cryptoManager,signerIdentifier);
            Certificate[] certChain = CertChainBuilder.buildChain(cryptoManager,getSignerId(signerIdentifier), inCRLCertStore,certStore,trustStore);

            certificateValidator.verifyAndValidate(certChain, checkDate, checkRegion, new EndEntityType(true,true), entireChain);
            certificateValidator.checkCRLServicePermissionInAppPermissions(CRLServicePermissions.VERSION_1,certChain);
        } catch (IOException e) {
            throw new InvalidCRLException("Error building certificate chain when verifying CRL.");
        }catch (InvalidCertificateException e){
            throw new InvalidCRLException("Error validating certificate chain of CRL: " + e.getMessage(),e);
        }

        try {
            ToBeSignedCrl crlContent = etsi102941CRLHelper.getToBeSignedCrl(crl);
            validateTime(crlContent,checkDate);
            if(certificateId != null) {
                etsi102941CRLHelper.checkRevoked(crlContent, certificateId);
            }
        } catch (IOException e) {
            throw new InvalidCRLException("Error decoding CRL when verifying CRL.");
        }
    }



    /**
     * Method to verify that the given CRL are valid against the specified time.
     *
     * @param crl the CRL to check time constraints for.
     * @param currentTime the expected time to verify the CRL against.
     * @throws InvalidCRLException if the given CRL was invalid for the specified time.
     * @throws BadArgumentException    if other argument was invalid when validation the CRL.
     */
    protected void validateTime(ToBeSignedCrl crl, Date currentTime) throws BadArgumentException, InvalidCRLException {
        Date startDate = crl.getThisUpdate().asDate();
        if(currentTime.before(startDate)){
            throw new InvalidCRLException("Invalid CRL, not yet valid.");
        }
        Date endDate = crl.getNextUpdate().asDate();
        if(currentTime.after(endDate)){
            throw new InvalidCRLException("CRL is expired.");
        }
    }
}

