    package br.ufsc.labsec.pbad.hiring.criptografia.assinatura;

    import org.bouncycastle.cms.*;
    import org.bouncycastle.jce.provider.BouncyCastleProvider;
    import org.bouncycastle.operator.*;
    import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
    import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

    import java.security.cert.X509Certificate;

    /**
     * Classe responsável por verificar a integridade de uma assinatura.
     */
    public class VerificadorDeAssinatura {

        /**
         * Verifica a integridade de uma assinatura digital no padrão CMS.
         *
         * @param certificado certificado do assinante.
         * @param assinatura  documento assinado.
         * @return {@code true} se a assinatura for íntegra, e {@code false} do
         * contrário.
         */
        public boolean verificarAssinatura(X509Certificate certificado,
                                           CMSSignedData assinatura) throws OperatorCreationException, CMSException {

            // Gera o verificador de informações de assinatura a partir do certificado do assinante
            SignerInformationVerifier signerInformationVerifier = this.geraVerificadorInformacoesAssinatura(certificado);

            // Pega as informações da assinatura dentro do CMS
            SignerInformation signerInformation = this.pegaInformacoesAssinatura(assinatura);

            // Verifica a integridade da assinatura utilizando o verificador de informações de assinatura
            return signerInformation.verify(signerInformationVerifier);
        }

        /**
         * Gera o verificador de assinaturas a partir das informações do assinante.
         *
         * @param certificado certificado do assinante.
         * @return Objeto que representa o verificador de assinaturas.
         */
        private SignerInformationVerifier geraVerificadorInformacoesAssinatura(X509Certificate certificado) throws OperatorCreationException {

            ContentVerifierProvider contentVerifierProvider = new JcaContentVerifierProviderBuilder().setProvider(new BouncyCastleProvider()).build(certificado);

            DigestCalculatorProvider digestCalculatorProvider = new JcaDigestCalculatorProviderBuilder().setProvider(new BouncyCastleProvider()).build();

            SignatureAlgorithmIdentifierFinder signatureAlgorithmIdentifierFinder = new DefaultSignatureAlgorithmIdentifierFinder();

            CMSSignatureAlgorithmNameGenerator signatureAlgorithmNameGenerator = new DefaultCMSSignatureAlgorithmNameGenerator();

            return new SignerInformationVerifier(signatureAlgorithmNameGenerator,
                                                signatureAlgorithmIdentifierFinder,
                                                contentVerifierProvider,
                                                digestCalculatorProvider);
        }

        /**
         * Classe responsável por pegar as informações da assinatura dentro do CMS.
         *
         * @param assinatura documento assinado.
         * @return Informações da assinatura.
         */
        private SignerInformation pegaInformacoesAssinatura(CMSSignedData assinatura) {
            // Retorna as informações da primeira assinatura encontrada dentro do CMS
            return  assinatura.getSignerInfos().getSigners().iterator().next();
        }

    }
