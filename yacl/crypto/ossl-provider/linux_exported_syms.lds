VERS_1.0 {
  # Export symbols in pybind.
  global:
    OSSL_provider_init;

  # Hide everything else.
  local:
    *;
};
