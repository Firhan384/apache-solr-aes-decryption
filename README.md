# apache-solr-aes-decryption

## how to run
- mvn clean project

## run unit test
- mvn test

## setup to apache solr
- copy data solr-aes-decrypt-1.0-SNAPSHOT-jar-with-dependencies.jar to /usr/solr-8.11.2/server/solr-webapp/webapp/WEB-INF/lib
- add this code to solrconfig.xml to your core data
1. <lib dir="${solr.install.dir:../../../..}/server/solr-webapp/webapp/WEB-INF/lib/" regex="solr-aes-decrypt-.*\.jar" />
2. <valueSourceParser name="aesdecrypt" class="com.example.solr.AESDecryptFunction" />
- then restart solr

## how to use
- fl=aesdecrypt(your_data_encrypted, "your_key")