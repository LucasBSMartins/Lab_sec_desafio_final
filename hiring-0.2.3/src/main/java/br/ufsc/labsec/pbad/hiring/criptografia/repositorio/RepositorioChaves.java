package br.ufsc.labsec.pbad.hiring.criptografia.repositorio;

import br.ufsc.labsec.pbad.hiring.Constantes;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * Essa classe representa um repositório de chaves do tipo PKCS#12.
 *
 * @see KeyStore
 */
public class RepositorioChaves {

    private KeyStore repositorio;
    private char[] senha;
    private String alias;

    /**
     * Construtor.
     */
    public RepositorioChaves(char[] senha, String alias) {
        try {
            this.repositorio = KeyStore.getInstance(Constantes.formatoRepositorio);
            this.senha = senha;
            this.alias = alias;
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
    }

    /**
     * Abre o repositório do local indicado.
     *
     * @param caminhoRepositorio caminho do PKCS#12.
     */
    public void abrir(String caminhoRepositorio) throws IOException, CertificateException, NoSuchAlgorithmException {
        this.repositorio.load(new FileInputStream(caminhoRepositorio), this.senha);
    }

    /**
     * Obtém a chave privada do PKCS#12.
     *
     * @return Chave privada.
     */
    public PrivateKey pegarChavePrivada() throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {
        return (PrivateKey) this.repositorio.getKey(this.alias, this.senha);
    }

    /**
     * Obtém do certificado do PKCS#12.
     *
     * @return Certificado.
     */
    public X509Certificate pegarCertificado() throws KeyStoreException {
        return (X509Certificate) this.repositorio.getCertificate(this.alias);
    }
}
