#!/bin/sh
mvn clean install
mvn fabric8:build
mvn fabric8:resource
mvn fabric8:deploy
kubectl get pods

