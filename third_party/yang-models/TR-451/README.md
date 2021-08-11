# TR-451: vOMCI YANG modules
* The project's YANG module development takes place in this Bitbucket repository.
* See the [SDN NFV](https://wiki.broadband-forum.org/display/BBF/SDN+and+NFV) wiki page for general details of the project.

## Sub-directories ##
The repository contains the following sub-directories:

* [standard](standard): YANG modules produced by other SDOs, which is kept here just for convenience
* [types](types): YANG modules containing common data type definitions that are useful in multiple modules
* [common](common): YANG modules which are common to the vOMCI network functions
* [olt](olt): YANG modules that would be implemented on a physical OLT
* [vomci-funcion](vomc-message): YANG modules that would be implemented on a vOMCI function
* [vomci-proxy](vomci-proxy): YANG modules that would be implemented on a vOMCI Proxy
* [voltmf](voltmf): YANG modules that would be implemented on a virtual OLT management function

## Branches ##
The repository contains the following branches:

* `develop` is the default branch and always contains everything that has been merged either directly to it or to one of the `release/xxx` branches
* `release/1.0` is used for developing the TR-451 YANG and its Corrigenda
* `master` will contain public releases, each of which will have a corresponding tag

Any changes that are merged to a `release/1.x` branch are automatically merged to higher (more recent) `release/1.x` branches and to `develop`. For example, a change to `release/1.0` is automatically merged to `develop`

There may also be `feature/xxx` branches that are used for complex features that are not yet ready to be merged into one of the above branches
