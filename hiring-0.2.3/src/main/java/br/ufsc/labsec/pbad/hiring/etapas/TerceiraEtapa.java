package br.ufsc.labsec.pbad.hiring.etapas;

import  br.ufsc.labsec.pbad.hiring.Constantes;
import br.ufsc.labsec.pbad.hiring.criptografia.certificado.EscritorDeCertificados;
import br.ufsc.labsec.pbad.hiring.criptografia.certificado.GeradorDeCertificados;
import br.ufsc.labsec.pbad.hiring.criptografia.chave.LeitorDeChaves;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;


import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;


/**
 * <b>Terceira etapa - gerar certificados digitais</b>
 * <p>
 * Aqui você terá que gerar dois certificados digitais. A identidade ligada
 * a um dos certificados digitais deverá ser a sua. A entidade emissora do
 * seu certificado será a AC-Raiz, cuja chave privada já foi previamente
 * gerada. Também deverá ser feito o certificado digital para a AC-Raiz,
 * que deverá ser autoassinado.
 * <p>
 * Os pontos a serem verificados para essa etapa ser considerada concluída
 * são os seguintes:
 * <ul>
 * <li>
 * emitir um certificado digital autoassinado no formato X.509 para a AC-Raiz;
 * </li>
 * <li>
 * emitir um certificado digital no formato X.509, assinado pela AC-Raiz. O
 * certificado deve ter as seguintes características:
 * <ul>
 * <li>
 * {@code Subject} deverá ser o seu nome;
 * </li>
 * <li>
 * {@code SerialNumber} deverá ser o número da sua matrícula;
 * </li>
 * <li>
 * {@code Issuer} deverá ser a AC-Raiz.
 * </li>
 * </ul>
 * </li>
 * <li>
 * anexar ao desafio os certificados emitidos em formato PEM;
 * </li>
 * <li>
 * as chaves utilizadas nessa etapa deverão ser as mesmas já geradas.
 * </li>
 * </ul>
 */
public class TerceiraEtapa {

    public static void executarEtapa() {
        GeradorDeCertificados geradorDeCertificados = new GeradorDeCertificados();

        // Lendo a chave privada da AC (Autoridade Certificadora) do disco
        PrivateKey privateKeyAC = LeitorDeChaves.lerChavePrivadaDoDisco(Constantes.caminhoChavePrivadaAc, Constantes.algoritmoChave);

        // Lendo a chave pública da AC do disco
        PublicKey publicKeyAC = LeitorDeChaves.lerChavePublicaDoDisco(Constantes.caminhoChavePublicaAc, Constantes.algoritmoChave);

        // Lendo a chave pública do usuário do disco
        PublicKey publicKeyUser = LeitorDeChaves.lerChavePublicaDoDisco(Constantes.caminhoChavePublicaUsuario, Constantes.algoritmoChave);

        // Gerando a estrutura do certificado da AC-raiz
        TBSCertificate tbsCertificateAC = geradorDeCertificados.gerarEstruturaCertificado(publicKeyAC,
                Constantes.numeroSerieAc,
                Constantes.nomeAcRaiz,
                Constantes.nomeAcRaiz,
                7 /*dias*/);

        // Gerando o valor da assinatura do certificado da AC-raiz
        DERBitString derBitStringAC = geradorDeCertificados.geraValorDaAssinaturaCertificado(tbsCertificateAC, privateKeyAC);

        // Gerando o certificado da AC-raiz
        DefaultSignatureAlgorithmIdentifierFinder finder = new DefaultSignatureAlgorithmIdentifierFinder();
        X509Certificate certificadoAC = geradorDeCertificados.gerarCertificado(tbsCertificateAC,
                finder.find(Constantes.algoritmoAssinatura),
                derBitStringAC);

        try {
            EscritorDeCertificados.escreveCertificado(Constantes.caminhoCertificadoAcRaiz, certificadoAC.getEncoded(), "CERTIFICATE");
            System.out.println("Certificado AC-Raiz salvo com sucesso.");
        } catch (CertificateEncodingException | IOException e) {
            e.printStackTrace();
        }

        // Gerando a estrutura do certificado do usuário
        TBSCertificate tbsCertificateUser = geradorDeCertificados.gerarEstruturaCertificado(publicKeyUser,
                Constantes.numeroDeSerie,
                Constantes.nomeUsuario,
                Constantes.nomeAcRaiz,
                7 /*dias*/);

        // Gerando o valor da assinatura do certificado do usuário
        DERBitString derBitStringUser = geradorDeCertificados.geraValorDaAssinaturaCertificado(tbsCertificateUser, privateKeyAC);

        // Gerando o certificado do usuário
        X509Certificate certificadoUser = geradorDeCertificados.gerarCertificado(tbsCertificateUser,
                finder.find(Constantes.algoritmoAssinatura),
                derBitStringUser);

        try {
            EscritorDeCertificados.escreveCertificado(Constantes.caminhoCertificadoUsuario, certificadoUser.getEncoded(), "CERTIFICATE");
            System.out.println("Certificado do usuário salvo com sucesso.");
        } catch (CertificateEncodingException | IOException e) {
            e.printStackTrace();
        }
    }
}
