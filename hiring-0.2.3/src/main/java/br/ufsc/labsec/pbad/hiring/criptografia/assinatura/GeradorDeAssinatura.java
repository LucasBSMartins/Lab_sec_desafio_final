package br.ufsc.labsec.pbad.hiring.criptografia.assinatura;

import br.ufsc.labsec.pbad.hiring.Constantes;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.cert.jcajce.JcaCertStore;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * Classe responsável por gerar uma assinatura digital.
 * <p>
 * Aqui será necessário usar a biblioteca Bouncy Castle, pois ela já possui a
 * estrutura básica da assinatura implementada.
 */
public class GeradorDeAssinatura {

    private X509Certificate certificado;
    private PrivateKey chavePrivada;
    private CMSSignedDataGenerator geradorAssinaturaCms;

    /**
     * Construtor.
     */
    public GeradorDeAssinatura() {
        this.geradorAssinaturaCms = new CMSSignedDataGenerator();
    }

    /**
     * Informa qual será o assinante.
     *
     * @param certificado  certificado, no padrão X.509, do assinante.
     * @param chavePrivada chave privada do assinante.
     */
    public void informaAssinante(X509Certificate certificado,
                                 PrivateKey chavePrivada) {
        this.certificado = certificado;
        this.chavePrivada = chavePrivada;
    }

    /**
     * Gera uma assinatura no padrão CMS.
     *
     * @param caminhoDocumento caminho do documento que será assinado.
     * @return Documento assinado.
     */
    public CMSSignedData assinar(String caminhoDocumento) throws CMSException, CertificateEncodingException {

        // Cria uma lista contendo o certificado usado para assinar
        List<X509Certificate> certList = new ArrayList<>();
        certList.add(this.certificado);

        CMSTypedData typedData = this.preparaDadosParaAssinar(caminhoDocumento);

        SignerInfoGenerator sig = this.preparaInformacoesAssinante(this.chavePrivada, this.certificado);

        // Adiciona as informações do assinante e os certificados à estrutura da assinatura CMS
        this.geradorAssinaturaCms.addSignerInfoGenerator(sig);
        this.geradorAssinaturaCms.addCertificates(new JcaCertStore(certList));

        // Gera a assinatura CMS,
        return geradorAssinaturaCms.generate(typedData, true);
    }


    /**
     * Transforma o documento que será assinado para um formato compatível
     * com a assinatura.
     *
     * @param caminhoDocumento caminho do documento que será assinado.
     * @return Documento no formato correto.
     */
    private CMSTypedData preparaDadosParaAssinar(String caminhoDocumento) {
        try(FileInputStream arquivoEntrada = new FileInputStream(caminhoDocumento)) {

            // Lê o documento para uma byte array
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            int nRead;
            byte[] bytes = new byte[arquivoEntrada.available()];
            while ((nRead = arquivoEntrada.read(bytes, 0, bytes.length)) != -1) {
                buffer.write(bytes, 0, nRead);
            }

            // Retorna os dados no formato CMSTypedData.
            return new CMSProcessableByteArray(bytes);
        } catch (IOException e){
            e.printStackTrace();
        }

        return null;
    }

        /**
         * Gera as informações do assinante na estrutura necessária para ser
         * adicionada na assinatura.
         *
         * @param chavePrivada chave privada do assinante.
         * @param certificado  certificado do assinante.
         * @return Estrutura com informações do assinante.
         */
        private SignerInfoGenerator preparaInformacoesAssinante(PrivateKey chavePrivada,
                                                                 Certificate certificado) {
            try {
                ContentSigner contentSigner = new JcaContentSignerBuilder(Constantes.algoritmoAssinatura).build(chavePrivada);

                // Retorna a estrutura com informações do assinante.
                return new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().build())
                        .build(contentSigner, (X509Certificate) certificado);
            } catch (OperatorCreationException | CertificateEncodingException e) {
                e.printStackTrace();
            }
            return null;
        }

        /**
     * Escreve a assinatura no local apontado.
     *
     * @param arquivo    arquivo que será escrita a assinatura.
     * @param assinatura objeto da assinatura.
     */
    public void escreveAssinatura(OutputStream arquivo, CMSSignedData assinatura) {
        try {
            arquivo.write(assinatura.getEncoded());
            arquivo.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

