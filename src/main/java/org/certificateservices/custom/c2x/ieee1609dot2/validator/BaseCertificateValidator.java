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
package org.certificateservices.custom.c2x.ieee1609dot2.validator;

import org.certificateservices.custom.c2x.common.BadArgumentException;
import org.certificateservices.custom.c2x.common.CertStore;
import org.certificateservices.custom.c2x.common.MapCertStore;
import org.certificateservices.custom.c2x.common.validator.*;
import org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.GeographicRegion;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId8;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.EndEntityType;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.IssuerIdentifier;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.CertChainBuilder;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * Base Class for validating a certificate chain, using time, region, permission and signature.
 *
 * @author Philip Vendil, p.vendil@cgi.com
 */
public abstract class BaseCertificateValidator implements CertificateValidator {

    protected Ieee1609Dot2CryptoManager cryptoManager;
    protected TimeValidator timeValidator;
    protected RegionValidator regionValidator;
    protected PermissionValidator permissionValidator;
    protected CertChainBuilder certChainBuilder;

    protected BaseCertificateValidator(Ieee1609Dot2CryptoManager cryptoManager,
                                       TimeValidator timeValidator,
                                       RegionValidator regionValidator,
                                       PermissionValidator permissionValidator){
        this.cryptoManager = cryptoManager;
        this.timeValidator = timeValidator;
        this.regionValidator = regionValidator;
        this.permissionValidator = permissionValidator;

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
     * @param certStore a certstore that contains all intermediate CA certificates that is needed to build the chain.
     * @param trustStore a certstore of root ca certificates that are trusted.
     * @param entireChain if entireChain should be validated or only first certificate in chain.
     * @throws BadArgumentException if one of the parameters where invalid.
     * @throws InvalidCertificateException if one of the certificate in the build certificate chain was invalid.
     * @throws NoSuchAlgorithmException if use hash algorithm isn't supported by the system.
     */
    public void verifyAndValidate(Certificate certificate, Date checkDate, GeographicRegion checkRegion,
                           EndEntityType targetEndEntityType, CertStore certStore,
                                  CertStore trustStore, boolean entireChain) throws BadArgumentException,
            InvalidCertificateException, NoSuchAlgorithmException{
        verifyAndValidate(certificate,checkDate,checkRegion,targetEndEntityType,0,certStore,trustStore, entireChain);
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
     * @param certStore a certstore that contains all intermediate CA certificates that is needed to build the chain.
     * @param trustStore a certstore of root ca certificates that are trusted.
     * @param entireChain if entireChain should be validated or only first certificate in chain.
     * @throws BadArgumentException if one of the parameters where invalid.
     * @throws InvalidCertificateException if one of the certificate in the build certificate chain was invalid.
     * @throws NoSuchAlgorithmException if use hash algorithm isn't supported by the system.
     */
    public void verifyAndValidate(Certificate certificate, Date checkDate, GeographicRegion checkRegion,
                           EndEntityType targetEndEntityType, int chainLengthIndex,
                                  CertStore certStore,
                                  CertStore trustStore, boolean entireChain)
            throws BadArgumentException, InvalidCertificateException, NoSuchAlgorithmException {

        Certificate[] certChain = buildCertChain(certificate, certStore, trustStore);
        verifyAndValidate(certChain,checkDate,checkRegion,targetEndEntityType,chainLengthIndex,entireChain);
    }

    /**
     * Method that verifies and validates all permissions on a known certificate chain data. The
     * end entity certificate should be in position 0 and root certificate last.
     * <p>
     * The method will build a chain for the certificate from the set of known certificates
     * and the trust anchors.
     * </p>
     * <p>
     * <p>
     * For each certificate in the built chain it will check.
     * <ul>
     * <li>Signature verifies</li>
     * <li>Certificates validity</li>
     * <li>Region matches</li>
     * <li>App Permissions/Cert Issue Permissions</li>
     * </ul>
     * <p>
     * <b>The method does not currently check revocation information.</b>
     * </p>
     * <p>
     * <b>Permissions is only checked that it is consistent upwards in the chain. It does not check a specific permission</b>
     * </p>
     *
     * @param certificateChain    the certificate chain to verify and validate. The
     *                            end entity certificate should be in position 0 and root certificate last.
     * @param checkDate           the date to check validity of certificate chain against.
     * @param checkRegion         the region to check against, if null is region check skipped.
     * @param targetEndEntityType the type of end entity tree to check.
     * @param entireChain if entireChain should be validated or only first certificate in chain.
     * @throws BadArgumentException    if one of the parameters where invalid.
     * @throws InvalidCertificateException if one of the certificate in the build certificate chain was invalid.
     * @throws NoSuchAlgorithmException    if use hash algorithm isn't supported by the system.
     */
    @Override
    public void verifyAndValidate(Certificate[] certificateChain, Date checkDate, GeographicRegion checkRegion,
                                  EndEntityType targetEndEntityType, boolean entireChain)
            throws BadArgumentException, InvalidCertificateException, NoSuchAlgorithmException {
        verifyAndValidate(certificateChain,checkDate,checkRegion,targetEndEntityType,0,entireChain);
    }

    /**
     * Method that verifies and validates all permissions on a known certificate chain data. The
     * end entity certificate should be in position 0 and root certificate last.
     * <p>
     * The method will build a chain for the certificate from the set of known certificates
     * and the trust anchors.
     * </p>
     * <p>
     * <p>
     * For each certificate in the built chain it will check.
     * <ul>
     * <li>Signature verifies</li>
     * <li>Certificates validity</li>
     * <li>Region matches</li>
     * <li>App Permissions/Cert Issue Permissions</li>
     * </ul>
     * <p>
     * <b>The method does not currently check revocation information.</b>
     * </p>
     * <p>
     * <b>Permissions is only checked that it is consistent upwards in the chain. It does not check a specific permission</b>
     * </p>
     *
     * @param certificateChain    the certificate chain to verify and validate. The
     *                            end entity certificate should be in position 0 and root certificate last.
     * @param checkDate           the date to check validity of certificate chain against.
     * @param checkRegion         the region to check against, if null is region check skipped.
     * @param targetEndEntityType the type of end entity tree to check.
     * @param chainLengthIndex    index parameter send to retrieve the correct group permissions from certificate. If validating chain that starts with end
     *                            entity certificate should chainLengthIndex be 0, if certificate chain starts with issuer of end entity certificate it should
     *                            be 1 and so on incremented up to root certificate in chain.
     * @param entireChain if entireChain should be validated or only first certificate in chain.
     * @throws BadArgumentException    if one of the parameters where invalid.
     * @throws InvalidCertificateException if one of the certificate in the build certificate chain was invalid.
     * @throws NoSuchAlgorithmException    if use hash algorithm isn't supported by the system.
     */
    @Override
    public void verifyAndValidate(Certificate[] certificateChain, Date checkDate, GeographicRegion checkRegion,
                                  EndEntityType targetEndEntityType, int chainLengthIndex, boolean entireChain)
            throws BadArgumentException, InvalidCertificateException, NoSuchAlgorithmException {

        timeValidator.validateTime(checkDate,certificateChain, entireChain);
        regionValidator.validateRegion(checkRegion,certificateChain);
        permissionValidator.checkPermissions(targetEndEntityType, chainLengthIndex, certificateChain,entireChain);
        verifyCertificateChain(certificateChain, entireChain);
    }

    /**
     * Help method to build a certificate chain with given certificate first up to root certificate last in
     * returned array.
     * @param certificate the certificate to build chain up to root ca for.
     * @param certStore store of known certificates ids to certificate, used to build up the chain to the trust store root certificates.
     * @param trustStore store of trusted root certificate ids to certificate.
     * @return a complete certificate chain up to root certificate.
     * @throws BadArgumentException if one of the parameters where invalid.
     * @throws InvalidCertificateException if one of the certificate in the build certificate chain was invalid.
     * @throws NoSuchAlgorithmException if use hash algorithm isn't supported by the system.
     */
    protected Certificate[] buildCertChain(Certificate certificate, CertStore certStore, CertStore trustStore) throws BadArgumentException, InvalidCertificateException, NoSuchAlgorithmException {
        try {
            HashedId8 certId = CertChainBuilder.getCertID(cryptoManager,certificate);
            Map<HashedId8, Certificate> signerStore = new HashMap<>();
            signerStore.put(certId, certificate);
            return CertChainBuilder.buildChain(cryptoManager,certId, new MapCertStore(signerStore), certStore, trustStore);
        }catch(IOException e){
            throw new InvalidCertificateException(e.getMessage(),e);
        }
    }

    /**
     * Method to verify the signature for all certificates in the chain up to the root certificate.
     * @param certChain the certificate chain to verify with end entity certificate first.
     * @param entireChain if entireChain should be validated or only first certificate in chain.
     * @throws InvalidCertificateException if one or more of the certificate up to root CA had invalid signature.
     */
    protected void verifyCertificateChain(Certificate[] certChain, boolean entireChain) throws InvalidCertificateException{
        try {
            if(certChain.length == 1){
                if (!cryptoManager.verifyCertificate(certChain[0], certChain[0])){
                    throw new InvalidCertificateException("Error verifying self signed certificate signature.");
                }
            }else {
                Certificate[] chain;
                if(entireChain){
                    chain = certChain;
                }else{
                    chain = new Certificate[] {certChain[0],certChain[1]};
                }
                for (int i = 1; i < chain.length; i++) {
                    if (!cryptoManager.verifyCertificate(chain[i - 1], chain[i])) {
                        throw new InvalidCertificateException("Error verifying signature of certificate in position " + (i - 1) + " in certificate chain.");
                    }
                }
            }
        }catch (Exception e){
            if(e instanceof InvalidCertificateException){
                throw (InvalidCertificateException) e;
            }
            throw new InvalidCertificateException("Error verifying signature of one the certificates in certificate chain.");
        }
    }

    /**
     * Method to check if issuer of certificate is self signed.
     * @param certificate the certificate to check
     * @return true if self signed.
     */
    public static boolean isSelfSigned(org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate certificate){
        return certificate.getIssuer().getType() == IssuerIdentifier.IssuerIdentifierChoices.self;
    }

    /**
     * Method to cast given certificate to ieee1609dot2 or throw BadArgumentException
     * if certificate is of wrong type.
     * @param certificateChain the certificate chain to cast to ieee1609dot2
     * @return ieee1609dot2 variant of the certificate
     * @throws BadArgumentException
     */
    public static org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate[] toIEEE1609Certificates(org.certificateservices.custom.c2x.common.Certificate[] certificateChain) throws BadArgumentException{
        org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate[] retval = new org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate[certificateChain.length];
        for(int i=0; i<certificateChain.length;i++){
            if(certificateChain[i] instanceof org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate){
                retval[i] = (org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate) certificateChain[i];
            }else {
                throw new BadArgumentException("Invalid certificate type: " + certificateChain[i].getClass().getName() + " expected of type " + org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate.class.getName());
            }
        }
        return retval;
    }
}
