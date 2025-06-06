#
# permissions error after a deploy?
# run below from terminal on direct2.directtrust.org
# sudo chown -R ec2-user:ec2-user /opt/direct/apache-tomcat-9.0.17/webapps/ROOT
#
scp -i "~/keypairs/EricKeyPair.pem" /Users/eric/git/direct-trust-utils/target/direct-trust-utils-1.1.jar ec2-user@direct2.directtrust.org:/opt/direct/apache-tomcat-9.0.17/webapps/ROOT/WEB-INF/lib
scp -i "~/keypairs/EricKeyPair.pem" /Users/eric/git/direct-trust-utils/target/direct-trust-utils-1.1.jar ec2-user@direct2.directtrust.org:/opt/direct/james-jpa-guice-3.2.0/james-server-jpa-guice.lib
