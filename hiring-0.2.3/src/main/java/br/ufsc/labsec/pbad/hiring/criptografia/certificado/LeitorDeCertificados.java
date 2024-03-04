package br.ufsc.labsec.pbad.hiring.criptografia.certificado;

import java.io.FileInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * Classe responsável por ler um certificado do disco.
 *
 * @see CertificateFactory
 */
public class LeitorDeCertificados {

    /**
     * Lê um certificado do local indicado.
     *
     * @param caminhoCertificado caminho do certificado a ser lido.
     * @return Objeto do certificado.
     */
    public static X509Certificate lerCertificadoDoDisco(String caminhoCertificado) {
        try {
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            FileInputStream inputStream = new FileInputStream(caminhoCertificado);
            X509Certificate certificate = (X509Certificate) certFactory.generateCertificate(inputStream);
            return certificate;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

}
