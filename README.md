# seal-control

Seal established a Root-Of-Trust (ROT) in a local trusted cluster. The cluster hardware and software should be entirely under control of the trusting team. Seal then use the resources of local trusted cluster to secure workloads running on remote untrusted clusters.

The images deployed on the remote untrusted clusters should be prepared and encrypted at a CI/CD running on the local cluster. Such images will inclue an egg that will be used by the pods running remotely to authenticate themself against the ROT and obtain the necessery keys for their workload. Such keys inlcude both mTLS keys and data encryption/dectryption keys. 

All workload pods should be designed to ensure all sensitive data is comunicated only via the provided mTLS credentials with peers of the same workload using their own provided mTLS credentials. Alternatively a workload pod may send/receive cypher data to anywhere outside the workload using the provided data encryption/dectryption keys. 

The key used for decrypting the image in remote clusters should be obtained through attenstation. The attstation service should also run on the local cluster. The CI/CD should obtain the egg from the ROT, embed it in the image and than decrypt it with the appropriate key coresponding to the one offered via the attestation service.




