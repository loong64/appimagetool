#! /bin/bash

set -euxo pipefail

if [[ "${2:-}" == "" ]]; then
    echo "Usage: $0 <version> <hash>"
    exit 2
fi

version="$1"
hash="$2"

build_dir="$(mktemp -d -t zsyncmake-build-XXXXXX)"

cleanup () {
    if [ -d "$build_dir" ]; then
        rm -rf "$build_dir"
    fi
}
trap cleanup EXIT

pushd "$build_dir"

# the original zsync homepage has been shut down apparently, but we can fetch the source code from most distros
wget http://deb.debian.org/debian/pool/main/z/zsync/zsync_"$version".orig.tar.bz2
echo "${hash}  zsync_${version}.orig.tar.bz2" | sha256sum -c

tar xf zsync_"$version"*.tar.bz2

cd zsync-*/

# custom patch to at least ignore flags passed after the first parameter
# see https://github.com/AppImage/appimagetool/pull/93 for more information
cat > argparser.patch <<\EOF
diff --git a/make.c b/make.c
index 191b527..d86f130 100644
--- a/make.c
+++ b/make.c
@@ -564,6 +564,14 @@ off_t get_len(FILE * f) {
  * Main program
  */
 int main(int argc, char **argv) {
+    if (getenv("VERBOSE") != 0) {
+        fprintf(stderr, "Parameters:");
+        for (int i = 0; i < argc; ++i) {
+            fprintf(stderr, " %s", argv[i]);
+        }
+        fprintf(stderr, "\n\n");
+    }
+
     FILE *instream;
     char *fname = NULL, *zfname = NULL;
     char **url = NULL;
@@ -641,7 +649,7 @@ int main(int argc, char **argv) {
         }
 
         /* Open data to create .zsync for - either it's a supplied filename, or stdin */
-        if (optind == argc - 1) {
+        if (optind <= argc - 1) {
             infname = strdup(argv[optind]);
             instream = fopen(infname, "rb");
             if (!instream) {
EOF

# custom patch to fix build on gcc-14
if [[ $(gcc -dumpversion) -gt 14 ]]; then

cat > fix-build-with-gcc-14.patch <<\EOF
Description: Fix build with GCC-14
Author: Marcos Talau <talau@debian.org>
Bug-Debian: https://bugs.debian.org/1075710
Forwarded: https://github.com/cph6/zsync/issues/20
Last-Update: 2024-08-16

Index: zsync-0.6.2/client.c
===================================================================
--- zsync-0.6.2.orig/client.c
+++ zsync-0.6.2/client.c
@@ -392,7 +392,7 @@ int fetch_remaining_blocks_http(struct z
  */
 int fetch_remaining_blocks(struct zsync_state *zs) {
     int n, utype;
-    const char *const *url = zsync_get_urls(zs, &n, &utype);
+    char **url = zsync_get_urls(zs, &n, &utype);
     int *status;        /* keep status for each URL - 0 means no error */
     int ok_urls = n;
 
@@ -452,7 +452,7 @@ extern long global_offset;
 int main(int argc, char **argv) {
     struct zsync_state *zs;
     char *temp_file = NULL;
-    char **seedfiles = NULL;
+    void **seedfiles = NULL;
     int nseedfiles = 0;
     char *filename = NULL;
     long long local_used;
Index: zsync-0.6.2/libzsync/zmap.c
===================================================================
--- zsync-0.6.2.orig/libzsync/zmap.c
+++ zsync-0.6.2/libzsync/zmap.c
@@ -333,7 +333,7 @@ int zmap_search(const struct zmap* zm, l
  * and in the order that it returned them, this condition is satisfied.
  */
 void configure_zstream_for_zdata(const struct zmap *zm, z_stream * zs,
-                                 long zoffset, long long *poutoffset) {
+                                 long zoffset, off_t *poutoffset) {
     /* Find the zmap entry corresponding to this offset */
     int i = zmap_search(zm, zoffset);
 
Index: zsync-0.6.2/libzsync/zmap.h
===================================================================
--- zsync-0.6.2.orig/libzsync/zmap.h
+++ zsync-0.6.2/libzsync/zmap.h
@@ -29,7 +29,7 @@ struct zmap* zmap_make(const struct gzbl
 void zmap_free(struct zmap*);
 
 off_t* zmap_to_compressed_ranges(const struct zmap* zm, off_t* byterange, int nrange, int* num);
-void configure_zstream_for_zdata(const struct zmap* zm, struct z_stream_s* zs, long zoffset, long long* poutoffset);
+void configure_zstream_for_zdata(const struct zmap* zm, struct z_stream_s* zs, long zoffset, off_t* poutoffset);
 
 /* gzip flag byte */
 #define GZ_ASCII_FLAG   0x01 /* bit 0 set: file probably ascii text */
Index: zsync-0.6.2/libzsync/zsync.c
===================================================================
--- zsync-0.6.2.orig/libzsync/zsync.c
+++ zsync-0.6.2/libzsync/zsync.c
@@ -436,7 +436,7 @@ void zsync_progress(const struct zsync_s
  * Note that these URLs could be for encoded versions of the target; a 'type'
  * is returned in *type which tells libzsync in later calls what version of the
  * target is being retrieved. */
-const char *const *zsync_get_urls(struct zsync_state *zs, int *n, int *t) {
+char **zsync_get_urls(struct zsync_state *zs, int *n, int *t) {
     if (zs->zmap && zs->nzurl) {
         *n = zs->nzurl;
         *t = 1;
@@ -768,7 +768,7 @@ char *zsync_end(struct zsync_state *zs)
  */
 void zsync_configure_zstream_for_zdata(const struct zsync_state *zs,
                                        struct z_stream_s *zstrm,
-                                       long zoffset, long long *poutoffset) {
+                                       long zoffset, off_t *poutoffset) {
     configure_zstream_for_zdata(zs->zmap, zstrm, zoffset, poutoffset);
     {                           /* Load in prev 32k sliding window for backreferences */
         long long pos = *poutoffset;
Index: zsync-0.6.2/libzsync/zsync.h
===================================================================
--- zsync-0.6.2.orig/libzsync/zsync.h
+++ zsync-0.6.2/libzsync/zsync.h
@@ -58,7 +58,7 @@ int zsync_submit_source_file(struct zsyn
  * (the URL pointers are still referenced by the library, and are valid only until zsync_end).
  */
 
-const char * const * zsync_get_urls(struct zsync_state* zs, int* n, int* t);
+char ** zsync_get_urls(struct zsync_state* zs, int* n, int* t);
 
 /* zsync_needed_byte_ranges - get the byte ranges needed from a URL.
  * Returns the number of ranges in *num, and a malloc'd array (to be freed 
EOF

fi

for i in *.patch; do
    echo "Applying patch $i..."
    patch -p1 < "$i"
done

find . -type f -exec sed -i -e 's|off_t|size_t|g' {} \;

./configure LDFLAGS=-static --prefix=/usr --build=$(arch)-unknown-linux-gnu

if [[ "${GITHUB_ACTIONS:-}" != "" ]]; then
    jobs="$(nproc)"
else
    jobs="$(nproc --ignore=1)"
fi

make -j"$jobs" install
