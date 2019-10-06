package org.jasypt.util.filehandler;

import java.util.Properties;

import org.apache.commons.io.FilenameUtils;

/**
 * Class to assign correct file handler after judging the fileName and type.
 * <b>This class is for internal use only</b>.
 * 
 * @author prakash.tiwari
 * 
 */
public class AssignHandler {
	public static FileHandler assign(Properties argumentValues) {
		if(argumentValues.containsKey("delimiter")) {
			String delimiter = argumentValues.getProperty("delimiter");
			String fileName = argumentValues.getProperty("inputfile");
			String fileType = FilenameUtils.getExtension(fileName);
			if(delimiter.equals(":") && (fileType.equals("yaml") || fileType.equals("yml"))) {
				return new YamlFileHandler();
			}
			else {
				return new SimpleSeparatedFileHandler();
			}
		}
		else {
			return new SimpleHandler();
		}
	}
}
