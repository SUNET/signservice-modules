#FROM openjdk:11-jre
FROM openjdk:18.0.2.1-slim

ADD target/edusign-signservice-*.jar /edusign-signservice.jar
ADD scripts/start.sh /start.sh
RUN chmod a+rx /start.sh

ENV JAVA_OPTS="-Dtomcat.ajp.enabled=true -Dtomcat.ajp.port=8009 -Dtomcat.ajp.secret-required=true -Dtomcat.ajp.secret=Hruje84u -Djava.net.preferIPv4Stack=true -Dorg.apache.xml.security.ignoreLineBreaks=true"

ENTRYPOINT /start.sh

EXPOSE 8443 8009
