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
package org.certificateservices.custom.c2x.etsits103097.v131.validator;

import org.certificateservices.custom.c2x.common.Certificate;
import org.certificateservices.custom.c2x.common.validator.*;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist.CtlEntry;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist.EtsiTs102941CRL;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist.EtsiTs102941CTL;
import org.certificateservices.custom.c2x.etsits102941.v131.validator.EtsiTs102941CRLValidator;
import org.certificateservices.custom.c2x.etsits102941.v131.validator.EtsiTs102941CTLValidator;
import org.certificateservices.custom.c2x.etsits103097.v131.AvailableITSAID;
import org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.GeographicRegion;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId8;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.EndEntityType;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.SecuredDataGenerator;
import org.certificateservices.custom.c2x.ieee1609dot2.validator.BaseCertificateValidator;
import org.certificateservices.custom.c2x.ieee1609dot2.validator.CountryOnlyRegionValidator;
import org.certificateservices.custom.c2x.ieee1609dot2.validator.Ieee1609Dot2TimeValidator;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.Date;
import java.util.Map;

/**
 * Certificate Validator for verifying and validating ETSI103097Certificates.
 * <p>
 *     The validator verifies the signature, region, validity and that permissions are consistent.
 * </p>
 * <p>
 *     For regions is only countryOnly regions allowed. No other.
 * </p>
 * @author Philip Vendil, p.vendil@cgi.com
 */
public class ETSI103097CertificateValidator extends BaseCertificateValidator {

    private static final CtlEntry.CtlEntryChoices[] ROOTCA_ENTRIES = {CtlEntry.CtlEntryChoices.rca};

    private EtsiTs102941CRLValidator etsiTs102941CRLValidator;
    private EtsiTs102941CTLValidator etsiTs102941CTLValidator;
    private SecuredDataGenerator securedDataGenerator;

    /**
     * Default certificate validator constructor.
     * @param cryptoManager the crypto manager to use for cryptographic operations.
     * @param securedDataGenerator the used secure data generator.
     */
    public ETSI103097CertificateValidator(Ieee1609Dot2CryptoManager cryptoManager, SecuredDataGenerator securedDataGenerator) {
        this(cryptoManager, securedDataGenerator, new Ieee1609Dot2TimeValidator(), new CountryOnlyRegionValidator(), new ETSI103097PermissionValidator());
    }

    /**
     * Flexible constructor where it is possible to override the validation checks.
     * @param cryptoManager the crypto manager to use for cryptographic operations.
     * @param securedDataGenerator the used secure data generator.
     * @param timeValidator a TimeValidator implementation
     * @param regionValidator a RegionValidation implementation
     * @param permissionValidator a ETSI103097PermissionValidator permission validator.
     */
    public ETSI103097CertificateValidator(Ieee1609Dot2CryptoManager cryptoManager, SecuredDataGenerator securedDataGenerator, TimeValidator timeValidator, RegionValidator regionValidator, ETSI103097PermissionValidator permissionValidator) {
        super(cryptoManager, timeValidator, regionValidator, permissionValidator);
        this.securedDataGenerator = securedDataGenerator;
        this.etsiTs102941CRLValidator = new EtsiTs102941CRLValidator(cryptoManager, securedDataGenerator, this);
        this.etsiTs102941CTLValidator = new EtsiTs102941CTLValidator(cryptoManager, securedDataGenerator, this);
    }

    /**
     * Method to check if the first certificate in supplied chain have a specific appPermission set in
     * its SecuredCertificateRequestService (623) SSP Data.
     *
     * @param ssPVersion the version byte of the SSP Data (Use SecuredCertificateRequestServicePermissions.VERSION_ constants)
     * @param ssPPermissions the permission to look up in the SSP Data (Use SecuredCertificateRequestServicePermission constants)
     * @param certificateChain the certificate chain to check permission, only the first certificate that have its certificate checked.
     * @throws InvalidCertificateException if given permission wasn't found in the certificate.
     */
    public void checkCertServicePermissionInAppPermissions(byte ssPVersion, byte ssPPermissions, Certificate[] certificateChain) throws InvalidCertificateException{
        ((ETSI103097PermissionValidator) permissionValidator).checkCertServicePermissionInAppPermissions(ssPVersion,ssPPermissions,certificateChain);
    }

    /**
     * Method to check if the first certificate in supplied chain have a specific appPermission set in
     * its CRLService (622) SSP Data.
     *
     * @param ssPVersion the version byte of the SSP Data (Use CRLServicePermissions.VERSION_ constants)
     * @param certificateChain the certificate chain to check permission, only the first certificate that have its certificate checked.
     * @throws InvalidCertificateException if given permission wasn't found in the certificate.
     */
    public void checkCRLServicePermissionInAppPermissions(byte ssPVersion, Certificate[] certificateChain) throws InvalidCertificateException{
        ((ETSI103097PermissionValidator) permissionValidator).checkCRLServicePermissionInAppPermissions(ssPVersion,certificateChain);
    }

    /**
     * Method to check if the first certificate in supplied chain have a specific appPermission set in
     * its CTLService (624) SSP Data.
     *
     * @param ssPVersion the version byte of the SSP Data (Use CTLServicePermissions.VERSION_ constants)
     * @param ssPPermissions the permission to look up in the SSP Data (Use CTLServicePermission constants)
     * @param certificateChain the certificate chain to check permission, only the first certificate that have its certificate checked.
     * @throws InvalidCertificateException if given permission wasn't found in the certificate.
     */
    public void checkCTLServicePermissionInAppPermissions(byte ssPVersion, byte ssPPermissions,Certificate[] certificateChain) throws InvalidCertificateException{
        ((ETSI103097PermissionValidator) permissionValidator).checkCTLServicePermissionInAppPermissions(ssPVersion,ssPPermissions,certificateChain);
    }

    /**
     * Method to check if the first certificate in supplied chain have a specific certIssuePermission set in
     * its SecuredCertificateRequestService (623) SSP Data.
     *
     * @param ssPVersion the version byte of the SSP Data (Use SecuredCertificateRequestServicePermissions.VERSION_ constants)
     * @param ssPPermissions the permission to look up in the SSP Data (Use SecuredCertificateRequestServicePermission constants)
     * @param endEntityType the end entity type to lookup
     * @param chainLengthIndex index parameter send to retrieve the correct group permissions from certificate. If validating chain that starts with end
     *                         entity certificate should chainLengthIndex be 0, if certificate chain starts with issuer of end entity certificate it should
     *                         be 1 and so on incremented up to root certificate in chain.
     * @param certificateChain the certificate chain to lookup cert issuer permissions if the first certificate.
     * @throws InvalidCertificateException if no given permissions was found in certificate.
     */
    public void checkCertServicePermissionInIssuePermissions(byte ssPVersion, byte ssPPermissions, EndEntityType endEntityType, int chainLengthIndex, Certificate[] certificateChain) throws InvalidCertificateException{
        ((ETSI103097PermissionValidator) permissionValidator).checkCertServicePermissionInIssuePermissions(ssPVersion,ssPPermissions,endEntityType,chainLengthIndex,certificateChain);
    }

    /**
     * Method that verifies and validates all permissions on the build certificate chain.
     * <p>
     *     The method will build a chain for the certificate from the set of known certificates
     *     and the trust anchors.
     * </p>
     *
     *
     * For each certificate in the built chain it will check.
     * <ul>
     *     <li>Signature verifies</li>
     *     <li>Certificates validity</li>
     *     <li>Region matches</li>
     *     <li>App Permissions/Cert Issue Permissions</li>
     *     <li>Verify Full Root CA CTL and delta Root CA CTL and validity</li>
     *     <li>Verify Root CA CRL</li>
     *     <li>Verify Full TLM CTL and delta TLM CTL and validity</li>
     * </ul>
     * <p>
     *   <b>The method does not currently check revocation information.</b>
     * </p>
     * <p>
     *   <b>Permissions is only checked that it is consistent upwards in the chain. It does not check a specific permission</b>
     * </p>
     *
     * @param certificate the certificate to verify and validate
     * @param checkDate the date to check validity of certificate chain against.
     * @param checkRegion the region to check against, if null is region check skipped.
     * @param targetEndEntityType the type of end entity tree to check.
     * @param fullRootCACTL the full RootCA CTL containing the EA and AA certificate used to build up a chain. Required.
     * @param deltaRootCACTL the delta RootCA CTL containing the delta information of EA and AA certificate. Use null
     *                       if no delta RootCA CTL is available.
     * @param rootCACRL the RootCA CRL to use to check revocation information of EA and AA certificate. Use null if
     *                  no revocation checks should be performed.
     * @param fullTLMCTL the Full TLM CTL of trusted root CA certificates used as trust store. Required.
     * @param deltaTLMCTL the delta TLM CTL containing the changes from the latest changes since full CTL was last issued.
     *                    Use null if no delta TLM CTL is available.
     * @param tlmCertificates a set of TLM trust used to verify the TLM certificate.
     * @param ctlTypes  the set of types to verify and return of CTL to verify and build store for. If DC Points
     *                  are going to be used it should be included in the array but they are not included in the
     *                  generated cert store.
     * @param entireChain if entireChain should be validated or only first certificate in chain.
     * @throws IllegalArgumentException if one of the parameters where invalid.
     * @throws InvalidCertificateException if one of the certificate in the build certificate chain was invalid.
     * @throws NoSuchAlgorithmException if use hash algorithm isn't supported by the system.
     * @throws InvalidCRLException if CRL was not verifiable or not within time constraints.
     * @throws CertificateRevokedException if one of the certificate in the build certificate chain was revoked.
     * @throws InvalidCRLException if CRL was not verifiable or not within time constraints.
     */
    public void verifyAndValidate(org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate certificate, Date checkDate, GeographicRegion checkRegion,
                                  EndEntityType targetEndEntityType,
                                  EtsiTs102941CTL fullRootCACTL, EtsiTs102941CTL deltaRootCACTL, EtsiTs102941CRL rootCACRL,
                                  EtsiTs102941CTL fullTLMCTL, EtsiTs102941CTL deltaTLMCTL, Certificate[] tlmCertificates,
                                  CtlEntry.CtlEntryChoices[] ctlTypes,
                                  boolean entireChain) throws IllegalArgumentException,
            InvalidCertificateException, NoSuchAlgorithmException, InvalidCTLException, CertificateRevokedException, InvalidCRLException {
        verifyAndValidate(certificate,checkDate,checkRegion,targetEndEntityType,0,fullRootCACTL, deltaRootCACTL, rootCACRL, fullTLMCTL, deltaTLMCTL,tlmCertificates, ctlTypes, entireChain);
    }

    /**
     * Method that verifies and validates all permissions on the build certificate chain.
     * <p>
     *     The method will build a chain for the certificate from the set of known certificates
     *     and the trust anchors.
     * </p>
     *
     *
     * For each certificate in the built chain it will check.
     * <ul>
     *     <li>Signature verifies</li>
     *     <li>Certificates validity</li>
     *     <li>Region matches</li>
     *     <li>App Permissions/Cert Issue Permissions</li>
     *     <li>Verify Full Root CA CTL and delta Root CA CTL and validity</li>
     *     <li>Verify Root CA CRL</li>
     *     <li>Verify Full TLM CTL and delta TLM CTL and validity</li>
     * </ul>
     * <p>
     *   <b>The method does not currently check revocation information.</b>
     * </p>
     * <p>
     *   <b>Permissions is only checked that it is consistent upwards in the chain. It does not check a specific permission</b>
     * </p>
     *
     * @param certificate the certificate to verify and validate
     * @param checkDate the date to check validity of certificate chain against.
     * @param checkRegion the region to check against, if null is region check skipped.
     * @param targetEndEntityType the type of end entity tree to check.
     * @param chainLengthIndex index parameter send to retrieve the correct group permissions from certificate. If validating chain that starts with end
     *                         entity certificate should chainLengthIndex be 0, if certificate chain starts with issuer of end entity certificate it should
     *                         be 1 and so on incremented up to root certificate in chain.
     * @param fullRootCACTL the full RootCA CTL containing the EA and AA certificate used to build up a chain. Required.
     * @param deltaRootCACTL the delta RootCA CTL containing the delta information of EA and AA certificate. Use null
     *                       if no delta RootCA CTL is available.
     * @param rootCACRL the RootCA CRL to use to check revocation information of EA and AA certificate. Use null if
     *                  no revocation checks should be performed.
     * @param fullTLMCTL the Full TLM CTL of trusted root CA certificates used as trust store. Required.
     * @param deltaTLMCTL the delta TLM CTL containing the changes from the latest changes since full CTL was last issued.
     *                    Use null if no delta TLM CTL is available.
     * @param tlmCertificates a set of TLM trust used to verify the TLM certificate.
     * @param ctlTypes  the set of types to verify and return of CTL to verify and build store for. If DC Points
     *                  are going to be used it should be included in the array but they are not included in the
     *                  generated cert store.
     * @param entireChain if entireChain should be validated or only first certificate in chain.
     * @throws IllegalArgumentException if one of the parameters where invalid.
     * @throws InvalidCertificateException if one of the certificate in the build certificate chain was invalid.
     * @throws NoSuchAlgorithmException if use hash algorithm isn't supported by the system.
     * @throws InvalidCRLException if CRL was not verifiable or not within time constraints.
     * @throws CertificateRevokedException if one of the certificate in the build certificate chain was revoked.
     * @throws InvalidCRLException if CRL was not verifiable or not within time constraints.
     */
    public void verifyAndValidate(org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate certificate, Date checkDate, GeographicRegion checkRegion,
                                  EndEntityType targetEndEntityType, int chainLengthIndex,
                                  EtsiTs102941CTL fullRootCACTL, EtsiTs102941CTL deltaRootCACTL, EtsiTs102941CRL rootCACRL,
                                  EtsiTs102941CTL fullTLMCTL, EtsiTs102941CTL deltaTLMCTL, Certificate[] tlmCertificates,
                                  CtlEntry.CtlEntryChoices[] ctlTypes,
                                  boolean entireChain)
            throws IllegalArgumentException, InvalidCertificateException, NoSuchAlgorithmException,
            InvalidCTLException, CertificateRevokedException, InvalidCRLException {
        org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate[] etsiTlmCertificates = toIEEE1609Certificates(tlmCertificates);
        Map<HashedId8, org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate> tlmTrustStore;
        try {
            tlmTrustStore = securedDataGenerator.buildCertStore(etsiTlmCertificates);
        } catch (IOException e) {
            throw new IllegalArgumentException("Unable to build TLM CTL certificate trust store: " + e.getMessage(),e);
        }
        Map<HashedId8, org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate> trustStore;
        try {
            trustStore = etsiTs102941CTLValidator.verifyAndValidate(fullTLMCTL, deltaTLMCTL, checkDate, tlmTrustStore, entireChain, ROOTCA_ENTRIES);
        }catch(IllegalArgumentException e){
            throw new InvalidCTLException("Invalid ECTL: " + e.getMessage(), e);
        }catch(InvalidCTLException e){
            throw new InvalidCTLException("Invalid ECTL: " + e.getMessage(), e);
        }catch(InvalidCertificateException e){
            throw new InvalidCertificateException("Invalid ECTL: " + e.getMessage(), e);
        }

        verifyAndValidate(certificate,checkDate,checkRegion,targetEndEntityType,chainLengthIndex,fullRootCACTL, deltaRootCACTL, rootCACRL, trustStore, ctlTypes, entireChain);
    }

    /**
     * Method that verifies and validates all permissions on the build certificate chain.
     * <p>
     *     The method will build a chain for the certificate from the set of known certificates
     *     and the trust anchors.
     * </p>
     *
     *
     * For each certificate in the built chain it will check.
     * <ul>
     *     <li>Signature verifies</li>
     *     <li>Certificates validity</li>
     *     <li>Region matches</li>
     *     <li>App Permissions/Cert Issue Permissions</li>
     *     <li>Verify Full Root CA CTL and delta Root CA CTL and validity</li>
     *     <li>Verify Root CA CRL</li>
     *     <li>Verify Full TLM CTL and delta TLM CTL and validity</li>
     * </ul>
     * <p>
     *   <b>The method does not currently check revocation information.</b>
     * </p>
     * <p>
     *   <b>Permissions is only checked that it is consistent upwards in the chain. It does not check a specific permission</b>
     * </p>
     *
     * @param certificate the certificate to verify and validate
     * @param checkDate the date to check validity of certificate chain against.
     * @param checkRegion the region to check against, if null is region check skipped.
     * @param targetEndEntityType the type of end entity tree to check.
     * @param fullRootCACTL the full RootCA CTL containing the EA and AA certificate used to build up a chain. Required.
     * @param deltaRootCACTL the delta RootCA CTL containing the delta information of EA and AA certificate. Use null
     *                       if no delta RootCA CTL is available.
     * @param rootCACRL the RootCA CRL to use to check revocation information of EA and AA certificate. Use null if
     *                  no revocation checks should be performed.
     * @param trustStore a cert store of root ca certificates that are trusted.
     * @param ctlTypes  the set of types to verify and return of CTL to verify and build store for. If DC Points
     *                  are going to be used it should be included in the array but they are not included in the
     *                  generated cert store.
     * @param entireChain if entireChain should be validated or only first certificate in chain.
     * @throws IllegalArgumentException if one of the parameters where invalid.
     * @throws InvalidCertificateException if one of the certificate in the build certificate chain was invalid.
     * @throws NoSuchAlgorithmException if use hash algorithm isn't supported by the system.
     * @throws InvalidCRLException if CRL was not verifiable or not within time constraints.
     * @throws CertificateRevokedException if one of the certificate in the build certificate chain was revoked.
     * @throws InvalidCRLException if CRL was not verifiable or not within time constraints.
     */
    public void verifyAndValidate(org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate certificate, Date checkDate, GeographicRegion checkRegion,
                                  EndEntityType targetEndEntityType,
                                  EtsiTs102941CTL fullRootCACTL, EtsiTs102941CTL deltaRootCACTL, EtsiTs102941CRL rootCACRL,
                                  Map<HashedId8, org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate> trustStore, CtlEntry.CtlEntryChoices[] ctlTypes,
                                  boolean entireChain) throws IllegalArgumentException,
            InvalidCertificateException, NoSuchAlgorithmException, InvalidCTLException, CertificateRevokedException, InvalidCRLException {
        verifyAndValidate(certificate,checkDate,checkRegion,targetEndEntityType,0, fullRootCACTL, deltaRootCACTL, rootCACRL, trustStore, ctlTypes, entireChain);
    }

    /**
     * Method that verifies and validates all permissions on the build certificate chain.
     * <p>
     *     The method will build a chain for the certificate from the set of known certificates
     *     and the trust anchors.
     * </p>
     *
     *
     * For each certificate in the built chain it will check.
     * <ul>
     *     <li>Signature verifies</li>
     *     <li>Certificates validity</li>
     *     <li>Region matches</li>
     *     <li>App Permissions/Cert Issue Permissions</li>
     *     <li>Verify Full Root CA CTL and delta Root CA CTL and validity</li>
     *     <li>Verify Root CA CRL</li>
     *     <li>Verify Full TLM CTL and delta TLM CTL and validity</li>
     * </ul>
     * <p>
     *   <b>The method does not currently check revocation information.</b>
     * </p>
     * <p>
     *   <b>Permissions is only checked that it is consistent upwards in the chain. It does not check a specific permission</b>
     * </p>
     *
     * @param certificate the certificate to verify and validate
     * @param checkDate the date to check validity of certificate chain against.
     * @param checkRegion the region to check against, if null is region check skipped.
     * @param targetEndEntityType the type of end entity tree to check.
     * @param chainLengthIndex index parameter send to retrieve the correct group permissions from certificate. If validating chain that starts with end
     *                         entity certificate should chainLengthIndex be 0, if certificate chain starts with issuer of end entity certificate it should
     *                         be 1 and so on incremented up to root certificate in chain.
     * @param fullRootCACTL the full RootCA CTL containing the EA and AA certificate used to build up a chain. Required.
     * @param deltaRootCACTL the delta RootCA CTL containing the delta information of EA and AA certificate. Use null
     *                       if no delta RootCA CTL is available.
     * @param rootCACRL the RootCA CRL to use to check revocation information of EA and AA certificate. Use null if
     *                  no revocation checks should be performed.
     * @param trustStore a cert store of root ca certificates that are trusted.
     * @param ctlTypes  the set of types to verify and return of CTL to verify and build store for. If DC Points
     *                  are going to be used it should be included in the array but they are not included in the
     *                  generated cert store.
     * @param entireChain if entireChain should be validated or only first certificate in chain.
     * @throws IllegalArgumentException if one of the parameters where invalid.
     * @throws InvalidCertificateException if one of the certificate in the build certificate chain was invalid.
     * @throws NoSuchAlgorithmException if use hash algorithm isn't supported by the system.
     * @throws InvalidCRLException if CRL was not verifiable or not within time constraints.
     * @throws CertificateRevokedException if one of the certificate in the build certificate chain was revoked.
     * @throws InvalidCRLException if CRL was not verifiable or not within time constraints.
     */
    public void verifyAndValidate(org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate certificate, Date checkDate, GeographicRegion checkRegion,
                                  EndEntityType targetEndEntityType, int chainLengthIndex,
                                  EtsiTs102941CTL fullRootCACTL, EtsiTs102941CTL deltaRootCACTL, EtsiTs102941CRL rootCACRL,
                                  Map<HashedId8, org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate> trustStore, CtlEntry.CtlEntryChoices[] ctlTypes,
                                  boolean entireChain)
            throws IllegalArgumentException, InvalidCertificateException, NoSuchAlgorithmException, InvalidCTLException, CertificateRevokedException, InvalidCRLException {

        Map<HashedId8, org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate> certStore = etsiTs102941CTLValidator.verifyAndValidate(fullRootCACTL,
                deltaRootCACTL,checkDate, trustStore, entireChain, ctlTypes);
        org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate[] certChain = buildCertChain(certificate, certStore, trustStore);
        if(rootCACRL != null && certChain.length > 1) {
            etsiTs102941CRLValidator.verifyAndValidate(rootCACRL, certChain[certChain.length-2], checkDate, trustStore, entireChain);
        }
        verifyAndValidate(certChain,checkDate,checkRegion,targetEndEntityType,chainLengthIndex,entireChain);
    }

}
