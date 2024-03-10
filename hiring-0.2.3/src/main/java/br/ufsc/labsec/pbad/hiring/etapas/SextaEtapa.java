package br.ufsc.labsec.pbad.hiring.etapas;

import br.ufsc.labsec.pbad.hiring.Constantes;
import br.ufsc.labsec.pbad.hiring.criptografia.assinatura.VerificadorDeAssinatura;
import br.ufsc.labsec.pbad.hiring.criptografia.repositorio.RepositorioChaves;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.operator.OperatorCreationException;


import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * <b>Sexta etapa - verificar uma assinatura digital</b>
 * <p>
 * Por último, será necessário verificar a integridade da assinatura
 * recém gerada. Note que o processo de validação de uma assinatura
 * digital pode ser muito complexo, mas aqui o desafio será simples. Para
 * verificar a assinatura será necessário apenas decifrar o valor da
 * assinatura (resultante do processo de cifra do resumo criptográfico do
 * arquivo {@code textoPlano.txt} com as informações da estrutura da
 * assinatura) e comparar esse valor com o valor do resumo criptográfico do
 * arquivo assinado. Como dito na fundamentação, para assinar é usada a chave
 * privada, e para decifrar (verificar) é usada a chave pública.
 * <p>
 * Os pontos a serem verificados para essa etapa ser considerada concluída
 * são os seguintes:
 * <ul>
 * <li>
 * verificar a assinatura gerada na etapa anterior, de acordo com o
 * processo descrito, e apresentar esse resultado.
 * </li>
 * </ul>
 */
public class SextaEtapa {

    public static void executarEtapa() {
       try (InputStream inputStream = new FileInputStream(Constantes.caminhoAssinatura);) {
           RepositorioChaves repositorio = new RepositorioChaves(Constantes.senhaMestre, Constantes.aliasUsuario);
           repositorio.abrir(Constantes.caminhoPkcs12Usuario);

           // Leitura da assinatura do arquivo e criação de um array de bytes
           ByteArrayOutputStream buffer = new ByteArrayOutputStream();
           int bytesRead;
           byte[] data = new byte[inputStream.available()];
           while ((bytesRead = inputStream.read(data, 0, data.length)) != -1) {
               buffer.write(data, 0, bytesRead);
           }

           // Criação de um CMSSignedData a partir dos dados da assinatura
           CMSSignedData cmsSignedData = new CMSSignedData(buffer.toByteArray());

           X509Certificate certificado = repositorio.pegarCertificado();

           // Verificação da assinatura utilizando o certificado e o objeto CMSSignedData
           VerificadorDeAssinatura verificadorDeAssinatura = new VerificadorDeAssinatura();
           if (verificadorDeAssinatura.verificarAssinatura(certificado, cmsSignedData)) {
               System.out.println("A assinatura é válida.");
           } else {
               System.out.println("A assinatura não é válida.");
           }
       } catch (IOException | KeyStoreException | CertificateException | NoSuchAlgorithmException |
                OperatorCreationException | CMSException e) {
           e.printStackTrace();
       }
    }

}
