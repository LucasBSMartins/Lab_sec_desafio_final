package br.ufsc.labsec.pbad.hiring.etapas;

import br.ufsc.labsec.pbad.hiring.Constantes;
import br.ufsc.labsec.pbad.hiring.criptografia.certificado.LeitorDeCertificados;
import br.ufsc.labsec.pbad.hiring.criptografia.chave.LeitorDeChaves;
import br.ufsc.labsec.pbad.hiring.criptografia.repositorio.GeradorDeRepositorios;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/**
 * <b>Quarta etapa - gerar repositório de chaves seguro</b>
 * <p>
 * Essa etapa tem como finalidade gerar um repositório seguro de chaves
 * assimétricas. Esse repositório deverá ser no formato PKCS#12. Note que
 * esse repositório é basicamente um tabela de espalhamento com pequenas
 * mudanças. Por exemplo, sua estrutura seria algo como {@code <Alias,
 * <Certificado, Chave Privada>>}, onde o _alias_ é um nome amigável dado a
 * uma entrada da estrutura, e o certificado e chave privada devem ser
 * correspondentes à mesma identidade. O _alias_ serve como elemento de busca
 * dessa identidade. O PKCS#12 ainda conta com uma senha, que serve para
 * cifrar a estrutura (isso é feito de modo automático).
 * <p>
 * Os pontos a serem verificados para essa etapa ser considerada concluída
 * são os seguintes:
 * <ul>
 * <li>
 * gerar um repositório para o seu certificado/chave privada com senha e
 * alias de acordo com as constantes fornecidas;
 * </li>
 * <li>
 * gerar um repositório para o certificado/chave privada da AC-Raiz com senha
 * e alias de acordo com as constantes fornecidas.
 * </li>
 * </ul>
 */
public class QuartaEtapa {

    public static void executarEtapa() {
        // Etapa para o repositório do usuário
        PrivateKey privateKeyUser = LeitorDeChaves.lerChavePrivadaDoDisco(Constantes.caminhoChavePrivadaUsuario, Constantes.algoritmoChave);
        X509Certificate certificadoUser = LeitorDeCertificados.lerCertificadoDoDisco(Constantes.caminhoCertificadoUsuario);
        String caminhoPcks12user = Constantes.caminhoPkcs12Usuario;
        String aliasUser = Constantes.aliasUsuario;
        char[] senha = Constantes.senhaMestre;

        // Gera o arquivo PKCS#12 para o repositório do usuário
        GeradorDeRepositorios.gerarPkcs12(privateKeyUser, certificadoUser, caminhoPcks12user, aliasUser, senha);
        System.out.println("Repositório do usuário gerado com sucesso.");

        // Etapa para o repositório da Autoridade Certificadora (AC)
        PrivateKey privateKeyAC = LeitorDeChaves.lerChavePrivadaDoDisco(Constantes.caminhoChavePrivadaAc, Constantes.algoritmoChave);
        X509Certificate certificadoAC = LeitorDeCertificados.lerCertificadoDoDisco(Constantes.caminhoCertificadoAcRaiz);
        String caminhoPcks12AC = Constantes.caminhoPkcs12AcRaiz;
        String aliasAC = Constantes.aliasAc;

        // Gera o arquivo PKCS#12 para o repositório da AC
        GeradorDeRepositorios.gerarPkcs12(privateKeyAC, certificadoAC, caminhoPcks12AC, aliasAC, senha);
        System.out.println("Repositório da AC-Raiz gerado com sucesso.");
    }

}
