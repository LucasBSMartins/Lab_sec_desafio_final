package br.ufsc.labsec.pbad.hiring.criptografia.certificado;

import br.ufsc.labsec.pbad.hiring.Constantes;

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
            CertificateFactory certFactory = CertificateFactory.getInstance(Constantes.formatoCertificado);

            FileInputStream inputStream = new FileInputStream(caminhoCertificado);

            // Gera um objeto X509Certificate a partir do conteúdo do arquivo usando a instância de CertificateFactory
            return (X509Certificate) certFactory.generateCertificate(inputStream);

        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

}
