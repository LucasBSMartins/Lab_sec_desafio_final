package br.ufsc.labsec.pbad.hiring.etapas;

import br.ufsc.labsec.pbad.hiring.Constantes;
import br.ufsc.labsec.pbad.hiring.criptografia.certificado.EscritorDeCertificados;
import br.ufsc.labsec.pbad.hiring.criptografia.certificado.GeradorDeCertificados;
import br.ufsc.labsec.pbad.hiring.criptografia.chave.LeitorDeChaves;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.NoSuchFileException;
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
        LeitorDeChaves leitorDeChaves = new LeitorDeChaves();
        EscritorDeCertificados escritorDeCertificados = new EscritorDeCertificados();


        PrivateKey privateKeyAC = leitorDeChaves.lerChavePrivadaDoDisco(Constantes.caminhoChavePrivadaAc, Constantes.algoritmoChave);
        PublicKey publicKeyAC = leitorDeChaves.lerChavePublicaDoDisco(Constantes.caminhoChavePublicaAc, Constantes.algoritmoChave);

        //PrivateKey privateKeyUser = leitorDeChaves.lerChavePrivadaDoDisco(Constantes.caminhoChavePrivadaUsuario, Constantes.algoritmoChave);
        PublicKey publicKeyUser = leitorDeChaves.lerChavePublicaDoDisco(Constantes.caminhoChavePublicaUsuario, Constantes.algoritmoChave);



        // Gerando certificado AC-raiz
        TBSCertificate tbsCertificateAC = geradorDeCertificados.gerarEstruturaCertificado(publicKeyAC,
                Constantes.numeroSerieAc,
                Constantes.nomeAcRaiz,
                Constantes.nomeAcRaiz,
                7 /*dias*/);

        DERBitString derBitStringAC = geradorDeCertificados.geraValorDaAssinaturaCertificado(tbsCertificateAC, privateKeyAC);


        DefaultSignatureAlgorithmIdentifierFinder finder = new DefaultSignatureAlgorithmIdentifierFinder();
        X509Certificate certificadoAC = geradorDeCertificados.gerarCertificado(tbsCertificateAC,
                finder.find(Constantes.algoritmoAssinatura),
                derBitStringAC);

        try {
            escritorDeCertificados.escreveCertificado(Constantes.caminhoCertificadoAcRaiz, certificadoAC.getEncoded(), "CERTIFICATE");
        } catch (CertificateEncodingException | IOException e) {
            e.printStackTrace();
        }

        //Gerando certificado user
        TBSCertificate tbsCertificateUser = geradorDeCertificados.gerarEstruturaCertificado(publicKeyUser,
                Constantes.numeroDeSerie,
                Constantes.nomeUsuario,
                Constantes.nomeAcRaiz,
                7 /*dias*/);

        DERBitString derBitStringUser = geradorDeCertificados.geraValorDaAssinaturaCertificado(tbsCertificateUser, privateKeyAC);

        X509Certificate certificadoUser = geradorDeCertificados.gerarCertificado(tbsCertificateUser,
                finder.find(Constantes.algoritmoAssinatura),
                derBitStringUser);

        try {
            escritorDeCertificados.escreveCertificado(Constantes.caminhoCertificadoUsuario, certificadoUser.getEncoded(), "CERTIFICATE");
        } catch (CertificateEncodingException | IOException e) {
            e.printStackTrace();
        }
    }
}
