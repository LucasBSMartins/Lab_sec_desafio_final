package br.ufsc.labsec.pbad.hiring.criptografia.certificado;

import br.ufsc.labsec.pbad.hiring.Constantes;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.jcajce.provider.asymmetric.x509.CertificateFactory;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.asn1.ASN1Object;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Calendar;
import java.util.Date;

import java.io.ByteArrayInputStream;
import java.security.cert.X509Certificate;

/**
 * Classe responsável por gerar certificados no padrão X.509.
 * <p>
 * Um certificado é basicamente composto por três partes, que são:
 * <ul>
 * <li>
 * Estrutura de informações do certificado;
 * </li>
 * <li>
 * Algoritmo de assinatura;
 * </li>
 * <li>
 * Valor da assinatura.
 * </li>
 * </ul>
 */

public class GeradorDeCertificados {

    /**
     * Gera a estrutura de informações de um certificado.
     *
     * @param chavePublica  chave pública do titular.
     * @param numeroDeSerie número de série do certificado.
     * @param nome          nome do titular.
     * @param nomeAc        nome da autoridade emissora.
     * @param dias          a partir da data atual, quantos dias de validade
     *                      terá o certificado.
     * @return Estrutura de informações do certificado.
     */
    public TBSCertificate gerarEstruturaCertificado(PublicKey chavePublica,
                                                    int numeroDeSerie, String nome,
                                                   String nomeAc, int dias) {

        // Obter informações da chave pública
        SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(chavePublica.getEncoded());

        // Definir o número de série
        ASN1Integer serialNumberASN1 = new ASN1Integer(numeroDeSerie);

        // Definir data de início
        Instant dataInicio = Instant.now();
        DERUTCTime startDate = new DERUTCTime(Date.from(dataInicio));

        // Definir data final adicionando 'dias' à data de início
        Instant dataFinal = dataInicio.plus(dias, ChronoUnit.DAYS);
        DERUTCTime endDate = new DERUTCTime(Date.from(dataFinal));

        // Definir informações da autoridade emissora
        X500Name issuer = new X500Name(nomeAc);

        // Definir informações do titular
        X500Name subject = new X500Name(nome);

        V3TBSCertificateGenerator tbsGen = new V3TBSCertificateGenerator();
        tbsGen.setSerialNumber(serialNumberASN1);
        tbsGen.setIssuer(issuer);
        tbsGen.setSubject(subject);

        // Acha o algoritmo usado para a assinatura
        DefaultSignatureAlgorithmIdentifierFinder finder = new DefaultSignatureAlgorithmIdentifierFinder();
        tbsGen.setSignature(finder.find(Constantes.algoritmoAssinatura));

        tbsGen.setSubjectPublicKeyInfo(publicKeyInfo);
        tbsGen.setStartDate(startDate);
        tbsGen.setEndDate(endDate);

        TBSCertificate tbsCertificate = tbsGen.generateTBSCertificate();

        return tbsCertificate;
    }

    /**
     * Gera valor da assinatura do certificado.
     *
     * @param estruturaCertificado estrutura de informações do certificado.
     * @param chavePrivadaAc       chave privada da AC que emitirá esse
     *                             certificado.
     * @return Bytes da assinatura.
     */
    public DERBitString geraValorDaAssinaturaCertificado(TBSCertificate estruturaCertificado,
                                                         PrivateKey chavePrivadaAc) {

        try {
            Signature assignature = Signature.getInstance(Constantes.algoritmoAssinatura);
            assignature.initSign(chavePrivadaAc);
            assignature.update(estruturaCertificado.getEncoded());

            DERBitString derBitString = new DERBitString(assignature.sign());
            return derBitString;
        } catch (NoSuchAlgorithmException | InvalidKeyException | IOException | SignatureException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Gera um certificado.
     *
     * @param estruturaCertificado  estrutura de informações do certificado.
     * @param algoritmoDeAssinatura algoritmo de assinatura.
     * @param valorDaAssinatura     valor da assinatura.
     * @return Objeto que representa o certificado.
     * @see ASN1EncodableVector
     */
    public X509Certificate gerarCertificado(TBSCertificate estruturaCertificado,
                                            AlgorithmIdentifier algoritmoDeAssinatura,
                                            DERBitString valorDaAssinatura) {

        try {
            ASN1EncodableVector encodableVector = new ASN1EncodableVector();

            encodableVector.add(estruturaCertificado);
            encodableVector.add(algoritmoDeAssinatura);
            encodableVector.add(valorDaAssinatura);
            DERSequence derSequence = new DERSequence(encodableVector);
            ByteArrayInputStream streamArray = new ByteArrayInputStream(derSequence.getEncoded());


            CertificateFactory certificateFactory = new CertificateFactory();
            return (X509Certificate) certificateFactory.engineGenerateCertificate(streamArray);

        } catch (IOException | CertificateException e) {
            e.printStackTrace();
        }
        return null;
    }

}
