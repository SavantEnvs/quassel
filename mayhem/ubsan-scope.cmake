# Loaded by mayhem/build.sh via -DCMAKE_PROJECT_Quassel_INCLUDE (fuzz build only; no upstream file changes).
# Relaxes exactly one UBSan check on exactly one source file: shift-base on src/core/cipher.cpp.
# FiSH base64 decoding there (Cipher::b64ToByte, `right |= v << (i * 6)` / `left |= v << (i * 6)`)
# shifts 6-bit values (or -1 for a char outside the alphabet) by up to 30 bits in an int on nearly every
# +OK ciphertext, which would halt fuzz_cipher on nearly every input. Everything else, including the rest
# of cipher.cpp's checks, stays fully sanitized. The flag lands on that file's compile line (cache-safe;
# no -fsanitize-ignorelist). Deferred to the end of the top-level directory so quassel_core exists.
function(mayhem_scope_cipher_shift_base)
  set_property(SOURCE "${CMAKE_SOURCE_DIR}/src/core/cipher.cpp"
    TARGET_DIRECTORY quassel_core
    APPEND PROPERTY COMPILE_OPTIONS "-fno-sanitize=shift-base")
endfunction()
cmake_language(DEFER DIRECTORY "${CMAKE_SOURCE_DIR}" CALL mayhem_scope_cipher_shift_base)
