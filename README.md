# jasypt
This is a fork of http://svn.code.sf.net/p/jasypt/code/trunk to add IV support for Java 8+ to allow higher encryption methods such as 'PBEWITHHMACSHA512ANDAES_256'.

## Jasypt integration for Spring boot

This fork will be used by the [Spring Boot Jasypt](https://github.com/ulisesbocchio/jasypt-spring-boot) project to add higher encryption levels to Spring Boot.

## Maven Central
```xml
<dependency>
  <groupId>com.melloware</groupId>
  <artifactId>jasypt</artifactId>
  <version>1.9.4</version>
</dependency>
```
## Command Line
If you would like to encrypt and decrypt using the [command line tools](http://www.jasypt.org/cli.html) you can download that version here:

[Download 1.9.4 CLI](https://github.com/melloware/jasypt/releases/download/1.9.4/jasypt-1.9.4.zip)
