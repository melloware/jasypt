package org.jasypt.util.filehandler;

import java.util.Properties;

import org.apache.commons.io.FilenameUtils;

/*
 * Class to assign correct file handler after judging the fileName and type
 */
public class AssignHandler {
	public static FileHandler assign(Properties argumentValues) {
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
}
