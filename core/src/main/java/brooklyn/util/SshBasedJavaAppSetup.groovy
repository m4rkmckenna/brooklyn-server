package brooklyn.util

import java.util.Map

import org.slf4j.Logger
import org.slf4j.LoggerFactory

import brooklyn.entity.basic.EntityLocal
import brooklyn.location.basic.SshMachineLocation
import brooklyn.util.internal.LanguageUtils

/**
 * Java application installation, configuration and startup using ssh.
 *
 * This class should be extended for use by entities that are implemented by a Java
 * application.
 *
 * TODO complete documentation
 */
public abstract class SshBasedJavaAppSetup extends SshBasedAppSetup {
    static final Logger log = LoggerFactory.getLogger(SshBasedJavaAppSetup.class)

    public static final int DEFAULT_FIRST_JMX_PORT = 32199

    protected boolean jmxEnabled = true
    protected int jmxPort
    protected Map<String,Map<String,String>> propFilesToGenerate = [:]
    protected Map<String,String> envVariablesToSet = [:]

    public SshBasedJavaAppSetup(EntityLocal entity, SshMachineLocation machine) {
        super(entity, machine)
    }

    public void setJmxEnabled(boolean val) {
        jmxEnabled = val
    }

    public void setJmxPort(int val) {
        jmxPort = val
    }

    public void setPropertyFiles(Map<String,Map<String,String>> propFilesToGenerate) {
        this.propFilesToGenerate = propFilesToGenerate
    }

    @Override
    public void config() {
        super.config()
        envVariablesToSet = generateAndCopyPropertyFiles()
    }

    private Map<String,String> generateAndCopyPropertyFiles() {
        Map<String,String> result = [:]
        
        // FIXME Store securely; may contain credentials!
        for (Map.Entry<String,Map<String,String>> entry in propFilesToGenerate) {
            String environmentVariableName = entry.key
            Map<String,String> propFileContents = entry.value

            Properties props = new Properties()
            for (Map.Entry<String,String> prop in propFileContents) {
                props.setProperty(prop.key, prop.value)
            }
            
            File tempFileOnDisk = File.createTempFile(entity.id, ".properties");
            FileOutputStream fos = new FileOutputStream(tempFileOnDisk)
            try {
                props.store(fos, "Auto-generated by Brooklyn; referenced by environment variable "+environmentVariableName)
                fos.flush()
                String uniqueFilePath = "${runDir}/"+LanguageUtils.newUid()+".properties"
                machine.copyTo tempFileOnDisk, uniqueFilePath
                
                result.put(environmentVariableName, uniqueFilePath)
            } finally {
                fos.close()
                tempFileOnDisk.delete()
            }
        }
        
        return result
    }
    
    /**
     * Convenience method to generate Java environment options string.
     *
     * Converts the properties {@link Map} entries with a value to {@code -Dkey=value}
     * and entries where the value is null to {@code -Dkey}.
     */
    public static String toJavaDefinesString(Map properties) {
        StringBuffer options = []
        properties.each { key, value ->
	            options.append("-D").append(key)
	            if (value != null && value != "") options.append("=\'").append(value).append("\'")
	            options.append(" ")
	        }
        return options.toString().trim()
    }

    @Override
    public Map<String, String> getRunEnvironment() {
        return envVariablesToSet
    }

    /**
     * Returns the complete set of Java configuration options required by
     * the application.
     *
     * These should be formatted and passed to the JVM as the contents of
     * the {@code JAVA_OPTS} environment variable. The default set contains
     * only the options required to enable JMX. To add application specific
     * options, override the {@link #getJavaConfigOptions()} method.
     *
     * @see #toJavaDefinesString(Map)
     */
    protected Map getJvmStartupProperties() {
        getJavaConfigOptions() + (jmxEnabled ? getJmxConfigOptions() : [:])
    }

    /**
     * Return extra Java configuration options required by the application.
     * 
     * This should be overridden; default is an empty {@link Map}.
     */
    protected Map getJavaConfigOptions() { return [:] }

    /**
     * Return the configuration properties required to enable JMX for a Java application.
     *
     * These should be set as properties in the {@code JAVA_OPTS} environment variable
     * when calling the run script for the application.
     *
     * TODO security!
     */
    protected Map getJmxConfigOptions() {
        [
          "com.sun.management.jmxremote" : "",
          "com.sun.management.jmxremote.port" : jmxPort,
          "com.sun.management.jmxremote.ssl" : false,
          "com.sun.management.jmxremote.authenticate" : false,
          "java.rmi.server.hostname" : machine.address.hostName,
        ]
    }
}
