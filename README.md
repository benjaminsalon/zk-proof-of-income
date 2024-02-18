# ZK-PROOF-OF-INCOME

Pluggable logic for implementng a privacy preserving proof of income on any smart contract. The code relies on a pytorch neural network able to classify income sheets images into categories of income.
The neural network is then compiled into a zk circuit thanks to [EZKL](https://github.com/zkonduit/ezkl) an amazing library for zkML. The user is then able to create a proof for its income. Only the output of the model and the hash of the input image
is public so that the exact income remains private while allowing to prove on-chain that the income is above a certain treshold.

A very good application of this could be foung in housing platform for allowing tenants to prove their income while maintaining privacy. The hash of the input being public, the tenant can reveal its original income sheet if required by law for instance.
Which allows for legal compliance.

This does not prevent against fake documents but neither does sending the fake documents to the landlord.



Big thanks to the EZKL team, which has been so helpful for accompanying me in this project!
