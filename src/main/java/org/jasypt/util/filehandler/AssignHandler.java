package org.jasypt.util.filehandler;

public class AssignHandler {
	public static FileHandler assign(String delimiter) {
		return new SimpleSeparatedFileHandler();
	}
}
