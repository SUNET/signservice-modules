FROM openjdk:18.0.2.1-slim

ADD target/edusign-signservice-*.jar /edusign-signservice.jar

RUN mkdir /opt/edusign-signservice

ENV JAVA_OPTS="-Djava.net.preferIPv4Stack=true -Dorg.apache.xml.security.ignoreLineBreaks=true"

ENTRYPOINT exec java $JAVA_OPTS -jar /edusign-signservice.jar

EXPOSE 8443 8444
