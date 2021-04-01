package main.control;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.util.encoders.Base64Encoder;

public class CryptoController {

	private static CryptoController instancia;

	public static CryptoController getInstancia() {
		if (instancia == null) {
			instancia = new CryptoController();
		}
		return instancia;
	}

	// cria uma assinatura a partir das chaves providas e assina o arquivo
	// provido no metodo utilizando os algoritmos RSA e SHA256
	public static String assinaRSAcomSHA256(FileInputStream pfx, FileInputStream arquivoOriginal, String senhaPfx, String aliasCertificado) {
		boolean sucesso = false;
		Security.addProvider(new BouncyCastleProvider());
		try {
			KeyStore keyStore = KeyStore.getInstance("PKCS12"); 

			//char[] password = { '1', '2', '3', '4', '5', '6', '7', '8', '9' }; // senha da private key provida

			//FileInputStream pfx = new FileInputStream("cert.p12");
			keyStore.load(pfx, senhaPfx.toCharArray());

			//FileInputStream inputDoc = new FileInputStream("doc.txt");
			byte[] texto = IOUtils.toByteArray(arquivoOriginal);

			List<X509Certificate> listaCertificados = new ArrayList<X509Certificate>();
			CMSTypedData mensagem = new CMSProcessableByteArray(texto);

			listaCertificados.add((X509Certificate) keyStore.getCertificate(aliasCertificado)); // pega o certificado com base no alias provido
																													
			PrivateKey chavePrivada = (PrivateKey) keyStore.getKey(aliasCertificado, senhaPfx.toCharArray()); // a private key propriamente dita

			JcaCertStore certificados = new JcaCertStore(listaCertificados);

			CMSSignedDataGenerator gerador = new CMSSignedDataGenerator();
			ContentSigner sha256Signer = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC")
					.build(chavePrivada);

			gerador.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
					new JcaDigestCalculatorProviderBuilder().setProvider("BC").build()).build(sha256Signer,
							(X509Certificate) keyStore.getCertificate(aliasCertificado)));

			gerador.addCertificates(certificados);

			CMSSignedData sigData = gerador.generate(mensagem, false);

	        String signedContent = Base64.getEncoder().encodeToString((byte[]) sigData.getSignedContent().getContent());
	        //System.out.println("Signed content: " + signedContent + "\n");

	        //String envelopedData = Base64.getEncoder().encodeToString((byte[]) sigData.getEncoded());
	        //System.out.println("Enveloped data: " + envelopedData);
	        sucesso = true;
	        
	        return signedContent;
			
	        
			/*
			String sigFile = "ArquivoAssinado.p7s";

			FileOutputStream outputAssinatura = new FileOutputStream(sigFile);
			outputAssinatura.write(sigData.getEncoded());
			
			sucesso = true;
			outputAssinatura.close();
			*/

		} catch (FileNotFoundException ex) {
			return "O arquivo selecionado nao pode ser localizado.";
		} catch (NoSuchAlgorithmException e) {
			return "Falha na localizacao do algoritmo selecionado.";
		} catch (CertificateException e) {
			return "Falha na leitura certificado selecionado.";
		} catch (IOException e) {
			return "Falha durante a leitura ou na escrita do arquivo.";
		} catch (KeyStoreException e) {
			return "Falha ao utilizar a Key Store selecionada.";
		} catch (UnrecoverableKeyException e) {
			return "O sistema falhou recuperar a chave do certificado selecionado.";
		} catch (OperatorCreationException e) {
			return "Falha na tentativa de localizar os arquivos de provedor de seguranca da biblioteca BC.";
		} catch (CMSException e) {
			return "Falha na inclusao dos certificados para assinatura.";
		} catch (Exception e) {
			return "Falha durante o procedimento.";
		}		
	}

	// metodo verificara autenticidade baseado no arquivo original, da assinatura
	// destacada provida.
	public static boolean verificaAutenticidadeAssDestacada(FileInputStream arquivo) {
		boolean sucesso = false;

		FileInputStream inputSig = null;

		try {
			inputSig = new FileInputStream("ArquivoAssinado.p7s"); 
		} catch (FileNotFoundException e2) {
			System.out.println("Falha na localizacao da assinatura.");
			return sucesso;
		} 

		byte[] sig = null;

		try {
			sig = IOUtils.toByteArray(inputSig);
		} catch (IOException e2) {
			System.out.println("Falha na leitura da assinatura.");
			return sucesso;
		} 

		/* FileInputStream inputDoc = null;
			try {
				inputDoc = new FileInputStream("doc.txt");
			} catch (FileNotFoundException e3) {
				System.out.println("O sistema nao obteve exito na localizacao do arquivo original.");
				return sucesso; 
			} */
		
		FileInputStream inputDoc = arquivo;

		byte[] dataBytes = null;

		try {
			dataBytes = IOUtils.toByteArray(inputDoc);
		} catch (IOException e2) {
			System.out.println("Falha na leitura do arquivo original.");
			return sucesso;
		}

		Security.addProvider(new BouncyCastleProvider());
		CMSSignedData dadosAssinados = null;
		CMSProcessableByteArray CMSArray = new CMSProcessableByteArray(dataBytes);

		try {
			dadosAssinados = new CMSSignedData(CMSArray, sig);
		} catch (CMSException e2) {
			System.out.println("Falha na verificacao do arquivo ou da assinatura.");
			return sucesso;
		}

		org.bouncycastle.util.Store<X509CertificateHolder> store = dadosAssinados.getCertificates();
		SignerInformationStore signatarios = dadosAssinados.getSignerInfos();
		Collection colSignatarios = signatarios.getSigners();
		Iterator iteraSig = colSignatarios.iterator();

		while (iteraSig.hasNext()) {
			SignerInformation signatario = (SignerInformation) iteraSig.next();
			Collection colCertificados = ((CollectionStore) store).getMatches(signatario.getSID());
			Iterator iteraCert = colCertificados.iterator();
			X509CertificateHolder responsavelCertificado = (X509CertificateHolder) iteraCert.next();
			X509Certificate certificadoPelaAssinatura = null;
			try {
				certificadoPelaAssinatura = new JcaX509CertificateConverter().setProvider("BC")
						.getCertificate(responsavelCertificado);
			} catch (CertificateException e1) {
				System.out.println(
						"Falha ao tentar gerar o certificado por meio da assinatura provida.");
				return sucesso;
			}

			try {
				if (signatario.verify(
						new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(certificadoPelaAssinatura))) {
					sucesso = true; // unico caso onde retorna true
					System.out.println("Assinatura verificada com sucesso.");
					return sucesso;
				} else {
					System.out.println("Falha na verificacao da assinatura.");
					return sucesso;
				}
			} catch (OperatorCreationException e) {
				System.out.println(
						"Falha na verificacao da assinatura. Verifique se o provedor de seguranca da lib BC esta incluso.");
			} catch (CMSException e) {
				System.out.println(
						"Falha na verificacao da assinatura, verifique se esta utilizando os arquivos corretos de assinatura e texto.");
			}
		}
		return sucesso; // sempre false quando chega ate aqui
	}
}
