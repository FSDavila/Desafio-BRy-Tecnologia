package main.control;

import java.io.File;
import java.io.FileInputStream;

import main.control.CryptoController;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import javax.servlet.http.HttpServletRequest;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("app")
public class FileRestController {
	
	private static String UPLOAD_DIR = "uploads";
	
	@RequestMapping(value = "signature", method = RequestMethod.POST) //endpoint /signature/
	public String signature(@RequestParam("pfx") MultipartFile pfx,@RequestParam("arquivo") MultipartFile arquivo, @RequestParam("senha") String senha, @RequestParam("alias") String alias, HttpServletRequest request) {
		String resultado = null;
		try {
			String nomePfx = pfx.getOriginalFilename();
			String nomeArquivo = arquivo.getOriginalFilename();
			String path = UPLOAD_DIR + File.separator;
			saveFile(pfx.getInputStream(), path + nomePfx);
			saveFile(pfx.getInputStream(), path + nomeArquivo);
			
			FileInputStream inputPfx = new FileInputStream(path+nomePfx);
			FileInputStream inputArq = new FileInputStream(path+nomeArquivo);
			
			resultado = CryptoController.assinaRSAcomSHA256(inputPfx, inputArq, senha, alias);
			
		} catch (IOException e) {
			return "Falha durante a leitura ou a escrita";
		} catch (Exception e) {
			return "Falha durante o processo";
		}
		if(resultado == null) {
			return "Falha na geracao da assinatura";
		}
		return resultado;
	}
	
	@RequestMapping(value = "verify", method = RequestMethod.POST) //endpoint /verify/
	public String verify(@RequestParam("arquivo") MultipartFile arquivo, HttpServletRequest request) {
		boolean sucesso = false;
		try {
			String fileName = arquivo.getOriginalFilename();
			String path = UPLOAD_DIR + File.separator + fileName;
			saveFile(arquivo.getInputStream(), path);
			FileInputStream inputSig = new FileInputStream(path);
			sucesso = CryptoController.verificaAutenticidadeAssDestacada(inputSig);			
		} catch (IOException e) {
			return "Falha durante a leitura ou a escrita";
		} catch (Exception e) {
			return "Falha durante a verificacao";
		}
		if(sucesso) {
			return "VALIDO";
		}
		return "INVALIDO";
	}
	
	private void saveFile(InputStream inputStream, String path) {
		try {
			OutputStream outputStream = new FileOutputStream(new File(path));
			int read = 0;
			byte[] bytes = new byte[1024];
			while ((read = inputStream.read(bytes)) != -1) {
				outputStream.write(bytes, 0, read);
			}
			outputStream.flush();
			outputStream.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
}
