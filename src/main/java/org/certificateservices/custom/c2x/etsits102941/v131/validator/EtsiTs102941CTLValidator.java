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

import org.certificateservices.custom.c2x.common.validator.CTLValidator;
import org.certificateservices.custom.c2x.common.validator.CertificateRevokedException;
import org.certificateservices.custom.c2x.common.validator.InvalidCTLException;
import org.certificateservices.custom.c2x.common.validator.InvalidCertificateException;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist.CtlEntry;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist.CtlFormat;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist.EtsiTs102941CTL;
import org.certificateservices.custom.c2x.etsits102941.v131.util.Etsi102941CTLHelper;
import org.certificateservices.custom.c2x.etsits103097.v131.validator.CTLServicePermissions;
import org.certificateservices.custom.c2x.etsits103097.v131.validator.ETSI103097CertificateValidator;
import org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.GeographicRegion;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId8;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.EndEntityType;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.SignerIdentifier;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.SecuredDataGenerator;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.Date;
import java.util.Map;

/**
 * EtsiTs102941CTLValidator contains method to verify and validate a CTL and check if a given certificate
 * is revoked.
 *
 * @author Philip Vendil 2020-02-04
 */
public class EtsiTs102941CTLValidator extends BaseEtsiTs102941ListValidator implements CTLValidator {

    protected Ieee1609Dot2CryptoManager cryptoManager;
    protected SecuredDataGenerator securedDataGenerator;
    protected ETSI103097CertificateValidator certificateValidator;
    protected Etsi102941CTLHelper etsi102941CTLHelper;

    /**
     * Constructor of CRL validator class.
     *
     * @param cryptoManager the crypto manager used.
     * @param securedDataGenerator the secured data generator used.
     * @param certificateValidator the certificate validator used.
     */
    public EtsiTs102941CTLValidator(Ieee1609Dot2CryptoManager cryptoManager, SecuredDataGenerator securedDataGenerator,
                                    ETSI103097CertificateValidator certificateValidator){
        super(cryptoManager);
        this.securedDataGenerator = securedDataGenerator;
        this.certificateValidator = certificateValidator;
        this.etsi102941CTLHelper = new Etsi102941CTLHelper(cryptoManager);
    }

    /**
     * Method that verifies and validates a CTL and returns a certStore of all valid cert entries
     * from given full CTL and optionally delta CTL.
     * <p>
     * The method will build a chain for the CTL from the set of trust anchors.
     * </p>
     * <p>
     * <p>
     * The following checks is done in the CTL.
     * <ul>
     * <li>Signature verifies</li>
     * <li>CTL validity</li>
     * <li>Issuing Certificate has permissions to issue CTLs</li>
     *
     * </ul>
     * <p>
     * <b>Permissions is only checked that it is consistent upwards in the chain. It does not check a specific permission</b>
     * </p>
     *
     * @param fullCTL     the full CTL to verify.
     * @param deltaCTL    the delta CTL to verify, use null if no delta CTL is available.
     * @param checkDate   the date to check validity of CRL and its certificate chain against.
     * @param trustStore  a certstore of root ca certificates that are trusted.
     * @param entireChain if entireChain should be validated or only CRL.
     * @param ctlTypes  the set of types to verify and return of CTL to verify and build store for. If DC Points
     *                  are going to be used it should be included in the array but they are not included in the
     *                  generated cert store.
     * @throws IllegalArgumentException    if one of the parameters where invalid.
     * @throws InvalidCTLException         if CTL was not verifyable or not within time constraints.
     * @throws InvalidCertificateException if one of the certificate in the build certificate chain was invalid.
     * @throws NoSuchAlgorithmException    if use hash algorithm isn't supported by the system.
     */
    @Override
    public Map<HashedId8, Certificate> verifyAndValidate(EtsiTs102941CTL fullCTL, EtsiTs102941CTL deltaCTL,
                                                         Date checkDate, Map<HashedId8, Certificate> trustStore,
                                                         boolean entireChain, CtlEntry.CtlEntryChoices[] ctlTypes)
            throws IllegalArgumentException, InvalidCTLException, InvalidCertificateException, NoSuchAlgorithmException {
        return verifyAndValidate(fullCTL, deltaCTL, checkDate, null, trustStore, entireChain, ctlTypes);
    }

    /**
     * Method that verifies and validates a CTL and returns a certStore of all valid cert entries
     * from given full CTL and optionally delta CTL.
     * <p>
     * The method will build a chain for the CTL from the set of trust anchors.
     * </p>
     * <p>
     * <p>
     * The following checks is done in the CTL.
     * <ul>
     * <li>Signature verifies</li>
     * <li>CTL validity</li>
     * <li>Issuing Certificate has permissions to issue CTLs</li>
     *
     * </ul>
     * <p>
     * <b>Permissions is only checked that it is consistent upwards in the chain. It does not check a specific permission</b>
     * </p>
     *
     * @param fullCTL     the full CTL to verify.
     * @param deltaCTL    the delta CTL to verify, use null if no delta CTL is available.
     * @param checkDate   the date to check validity of CRL and its certificate chain against.
     * @param certStore   a certstore that contains all intermediate CA certificates that is needed to build the chain.
     * @param trustStore  a certstore of root ca certificates that are trusted.
     * @param entireChain if entireChain should be validated or only CRL.
     * @param ctlTypes  the set of types to verify and return of CTL to verify and build store for. If DC Points
     *                  are going to be used it should be included in the array but they are not included in the
     *                  generated cert store.
     * @throws IllegalArgumentException    if one of the parameters where invalid.
     * @throws InvalidCTLException         if CTL was not verifiable or not within time constraints.
     * @throws InvalidCertificateException if one of the certificate in the build certificate chain was invalid.
     * @throws NoSuchAlgorithmException    if use hash algorithm isn't supported by the system.
     */
    @Override
    public Map<HashedId8, Certificate> verifyAndValidate(EtsiTs102941CTL fullCTL, EtsiTs102941CTL deltaCTL,
                                                         Date checkDate, Map<HashedId8, Certificate> certStore,
                                                         Map<HashedId8, Certificate> trustStore, boolean entireChain,
                                                         CtlEntry.CtlEntryChoices[] ctlTypes)
            throws IllegalArgumentException, InvalidCTLException, InvalidCertificateException, NoSuchAlgorithmException {
        if(certStore == null){
            certStore = emptyStore;
        }
        try {
            if(!securedDataGenerator.verifySignedData(fullCTL,certStore, trustStore)){
                throw new InvalidCTLException("Couldn't verify the full CTL.");
            }
        } catch (SignatureException e) {
            throw new InvalidCTLException("Couldn't verify full CTL signature: " + e.getMessage(),e);
        } catch (IOException e) {
            throw new InvalidCTLException("Couldn't decode full CTL data: " + e.getMessage(),e);
        }catch(IllegalArgumentException e){
            throw new InvalidCTLException("CTL Issuer not trusted: " + e.getMessage(),e);
        }

        VerifyCTLResult fullResult = verifyAndValidate(fullCTL, checkDate, certStore, trustStore,
                entireChain,ctlTypes,true,true, null);

        if(deltaCTL != null){
            VerifyCTLResult deltaResult = verifyAndValidate(deltaCTL, checkDate, certStore, trustStore,
                    entireChain,ctlTypes,false,false, null);

            if(deltaResult.ctlFormat.getCtlSequence() != fullResult.ctlFormat.getCtlSequence()){
                throw new InvalidCTLException("Error deltaCTL sequence doesn't match sequence in full CTL.");
            }

            if(!deltaResult.cTLSignerIdentifier.equals(fullResult.cTLSignerIdentifier)){
                throw new InvalidCTLException("Full CTL and delta CTL signerIdentifiers doesn't match.");
            }
        }

        try {
            return etsi102941CTLHelper.buildStore(fullCTL, deltaCTL, ctlTypes);
        } catch (IOException e) {
            throw new InvalidCTLException("Error building certificate store from CTL: " + e.getMessage(), e);
        }
    }

    /**
     * Method that verifies and validates a single CTL
     * <p>
     * The method will build a chain for the CTL from the set of trust anchors.
     * </p>
     * <p>
     * <p>
     * The following checks is done in the CTL.
     * <ul>
     * <li>Signature verifies</li>
     * <li>CTL validity</li>
     * <li>Issuing Certificate has permissions to issue CTLs</li>
     *
     * </ul>
     * <p>
     * <b>Permissions is only checked that it is consistent upwards in the chain. It does not check a specific permission</b>
     * </p>
     *
     * @param cTL     the cTL to verify.
     * @param checkDate   the date to check validity of CRL and its certificate chain against.
     * @param certStore   a certstore that contains all intermediate CA certificates that is needed to build the chain.
     * @param trustStore  a certstore of root ca certificates that are trusted.
     * @param entireChain if entireChain should be validated or only CRL.
     * @param ctlTypes  the set of types to verify and return of CTL to verify and build store for. If DC Points
     *                  are going to be used it should be included in the array but they are not included in the
     *                  generated cert store.
     * @param expectFull if a full CTL is expected
     * @param verifyChain if the signing certificate and it's chain should be verified.
     * @param region the region to be checked
     * @throws IllegalArgumentException    if one of the parameters where invalid.
     * @throws InvalidCTLException         if CTL was not verifiable or not within time constraints.
     * @throws InvalidCertificateException if one of the certificate in the build certificate chain was invalid.
     * @throws NoSuchAlgorithmException    if use hash algorithm isn't supported by the system.
     */
    public VerifyCTLResult verifyAndValidate(EtsiTs102941CTL cTL,
                                             Date checkDate, Map<HashedId8, Certificate> certStore,
                                             Map<HashedId8, Certificate> trustStore, boolean entireChain,
                                             CtlEntry.CtlEntryChoices[] ctlTypes,
                                             boolean expectFull, boolean verifyChain, GeographicRegion region)
            throws IllegalArgumentException, InvalidCTLException, InvalidCertificateException, NoSuchAlgorithmException {

        if(certStore == null){
            certStore = emptyStore;
        }

        String type = expectFull ? "full" : "delta";
        try {
            if(!securedDataGenerator.verifySignedData(cTL,certStore, trustStore)){
                throw new InvalidCTLException("Couldn't verify the " + type + " CTL.");
            }
        } catch (SignatureException e) {
            throw new InvalidCTLException("Couldn't verify " + type + " CTL signature: " + e.getMessage(),e);
        } catch (IOException e) {
            throw new InvalidCTLException("Couldn't decode "+ type + " CTL data: " + e.getMessage(),e);
        }catch(IllegalArgumentException e){
            throw new InvalidCTLException("CTL Issuer not trusted: " + e.getMessage(),e);
        }

        SignerIdentifier cTLSignerIdentifier;
        try {
            cTLSignerIdentifier = findSignerIdentifier(cTL);
            if(verifyChain) {
                Map<HashedId8, Certificate> inCRLCertStore = securedDataGenerator.getSignedDataStore(cTLSignerIdentifier);
                Certificate[] certChain = certChainBuilder.buildChain(getSignerId(cTLSignerIdentifier), inCRLCertStore, certStore, trustStore);

                certificateValidator.verifyAndValidate(certChain, checkDate, region, new EndEntityType(true, true), entireChain);
                certificateValidator.checkCTLServicePermissionInAppPermissions(CTLServicePermissions.VERSION_1, CTLServicePermissions.getPermissions(ctlTypes), certChain);
            }
        } catch (IOException e) {
            throw new InvalidCTLException("Error building certificate chain when verifying " + type + " CTL.");
        }catch (InvalidCertificateException e){
            throw new InvalidCTLException("Error validating certificate chain of " + type + " CTL: " + e.getMessage(),e);
        }

        CtlFormat ctlFormat;
        try{
            ctlFormat = etsi102941CTLHelper.getCtlFormat(cTL);
            validateTime(ctlFormat,checkDate, type);

            if((ctlFormat.isFullCtl() && !expectFull) || (!ctlFormat.isFullCtl() && expectFull)){
                String invType = expectFull ?  "delta" : "full";
                throw new InvalidCTLException("Invalid CTL type, expected " + type + " but CTL was of type: " + invType);
            }
        }catch (IOException e){
            throw new InvalidCTLException("Error parsing " + type + " CTL: " + e.getMessage(),e);
        }

        return new VerifyCTLResult(ctlFormat, cTLSignerIdentifier);
    }

    /**
     * Method to verify that the given CTL are valid against the specified time.
     *
     * @param ctlFormat the CTL to check time constraint for.
     * @param currentTime the expected time to verify the ctl against.
     * @throws InvalidCTLException if the given CTL was invalid for the specified time.
     * @throws IllegalArgumentException    if other argument was invalid when validation the CTL.
     */
    protected void validateTime(CtlFormat ctlFormat, Date currentTime, String type) throws IllegalArgumentException,
            InvalidCTLException {
        Date endDate = ctlFormat.getNextUpdate().asDate();
        if(currentTime.after(endDate)){
            throw new InvalidCTLException(type + " CTL is expired.");
        }
    }

    /**
     * Result of verifying a single CTL verification.
     */
    private static class VerifyCTLResult{
        CtlFormat ctlFormat;
        SignerIdentifier cTLSignerIdentifier;

        private VerifyCTLResult(CtlFormat ctlFormat, SignerIdentifier cTLSignerIdentifier){
            this.ctlFormat = ctlFormat;
            this.cTLSignerIdentifier = cTLSignerIdentifier;
        }
    }
}

