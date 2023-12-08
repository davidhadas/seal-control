# seal-control

Seal established a Root-Of-Trust (ROT) in a local trusted cluster. The cluster hardware and software should be entirely under control of the trusting team. Seal then use the resources of local trusted cluster to secure workloads running on remote untrusted clusters.

The images deployed on the remote untrusted clusters should be prepared and encrypted at a CI/CD running on the local cluster. Such images will inclue an Egg that will be used by the pods running remotely to authenticate themself against the ROT and obtain the necessery keys for their workload. Such keys inlcude both mTLS keys and data encryption/dectryption keys. 

All workload pods should be designed to ensure all sensitive data is comunicated only via the provided mTLS credentials with peers of the same workload using their own provided mTLS credentials. Alternatively a workload pod may send/receive cypher data to anywhere outside the workload using the provided data encryption/dectryption keys. 

The key used for decrypting the image in remote clusters should be obtained through attenstation. The attstation service should also run on the local cluster. The CI/CD should obtain the Egg from the ROT, embed it in the image and than decrypt it with the appropriate key coresponding to the one offered via the attestation service.

## Certificates
The package manages certificate athorities (CAs) and certificates used for mTLS. It manages a Seal wide CA used for the ROT. Further, it manages a per Workload CA. The Egg includes cypher used for identifying the specifics of a workload image including the workload name and a peer name. The default peer name is "any". Any pod created with the image obtains an adhoc certificate signed by the workload CA and carrying the peer name.

## mTLS between pods on the same cluster
Pods certificates are used both for client and for server side udner mTLS. Clients and Servers verify that the peer is signed with the Worklaod CA and carry the the SAN "any". Optionaly, Clients and Servers may also verify specific peer names. 

## mTLS between pods on different clusters 
For m2m communication patterns across cloud bounderies, set the Kubernetes services with Openshift passthrough Routes to allow end-to-end mTLS communication. This reuqires (1) SNI to be set to the hostanme (which is the default behavior for SNI), (2) the client to use a verification method that does not rely on the hostname to be part of the server presented certificate SANs. An example golang client is included here. 

External clients runing on a trusted cluster may also use mTLS to communicate with the pods on remote untrusted clusters by obtaining certificates signed by the workload CA from the ROT. 


#TBD
1. Can we avoid duplicating rotURL from RotCA to all WorkloadCAs?
1. 

## Https or HTTP between a standard external client and the workload pods
For use cases where standard external clients (such as browsers) need to communicate with the workload, all standard communication patterns are supported. It is up to the workload owner to consider the security implications of any data sent to, or received from, such cleints.   

In case https is required, standard methodologies should be applied for signing the server certificate with public CAs. Where client side authentication is also required, standard mechanisms can be applied. 


