Different Types of Security File formats explained here:

https://serverfault.com/questions/9708/what-is-a-pem-file-and-how-does-it-differ-from-other-openssl-generated-key-file

HTTP Messaging Signing explained here:

https://api-docs.form3.tech/tutorial-request-signing.html

Security Provider - BouncyCastle (Better API to read security files)
 
https://www.bouncycastle.org/

Command to generate Kubernetes Secret

kubectl create secret generic form3-keys --from-file=private_key=./private_key.pem --from-file=public_key=./public_key.pem

How to use Fabric8-MVN

https://medium.com/@rohaan/using-fabric8-maven-plugin-to-handle-your-kubernetes-openshift-operations-b40f6d3ae63f

https://www.baeldung.com/spring-boot-deploy-openshift

https://tomd.xyz/spring-boot-kubernetes/


Troubleshooting

https://managedkube.com/kubernetes/k8sbot/troubleshooting/imagepullbackoff/2019/02/23/imagepullbackoff.html