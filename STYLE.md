# C++ coding style

Yacl follows the [Envoy C++ style guidelines](https://github.com/envoyproxy/envoy/blob/main/STYLE.md), i.e. we also encourage appropriate exception uses.

## The scope of functions and classes

 To limit the scope of a function or class to the current file, use an anonymous namespace. For functions or classes within a namespace that shares the same name as the repository (repo), ensure they are thoroughly covered by tests and can be used normally by other repos. Sub-namespaces under a repo-named namespace may be used for interactions between different internal packages, and there is no strict requirement for their stability. If external repos need to use them, they must verify their suitability and stability independently. For functional changes in non-anonymous namespaces, ensure that the changelog is updated accordingly.
