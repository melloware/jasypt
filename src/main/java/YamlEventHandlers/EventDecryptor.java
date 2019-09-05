package YamlEventHandlers;

import java.io.StringReader;
import java.util.Properties;

import org.jasypt.intf.cli.JasyptEncryptorUtil;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.events.Event;
import org.yaml.snakeyaml.events.ScalarEvent;


public class EventDecryptor {
	public Event decryptValueInScalarEvent(Event event, Properties argumentValues) throws Exception{
		JasyptEncryptorUtil encryptor = new JasyptEncryptorUtil(argumentValues);
		String inputValue = ((ScalarEvent) event).getValue();
		if (inputValue.length() == 0) return event;
		else { // Remove "ENC()" from your string to decrypt
			inputValue = unwrap(inputValue);
		}
		String decryptedValue = encryptor.decrypt(inputValue);
		((ScalarEvent) event).setValue(decryptedValue);
		return event;
	}
	
	private String unwrap(String val){
		Exception exception = new Exception();
		try {
			if(val.length() < 5 || !val.substring(0, 4).equals("ENC(") || !val.substring(val.length() - 1).equals(")")) {
				throw exception;
			}
			String unwrapped = val.substring(4, val.length() - 1);
			return unwrapped;
		}
		catch(Exception e) {
			System.out.println("Ill formatted string recieved for decryption: \""+ val + "\"."
					+ "Please note that the encrypted value must be prefixed with \"ENC(\" and suffixed with \")\"");
			return val;
		}
	}
}
