extern "C" {
    pub fn i2d_re_X509_tbs(
        x: *const openssl_sys::X509,
        out: *mut *mut std::os::raw::c_uchar,
    ) -> std::os::raw::c_int;
}