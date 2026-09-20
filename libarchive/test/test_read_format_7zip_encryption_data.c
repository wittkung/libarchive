/*-
 * Copyright (c) 2013 Konrad Kleine
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR(S) ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR(S) BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include "test.h"

#define __LIBARCHIVE_BUILD 1
#include "archive_cryptor_private.h"

DEFINE_TEST(test_read_format_7zip_encryption_data)
{
	/* This file is password protected (encrypted) with AES-256. The headers
	   are NOT encrypted. Password is "12345678". */
	const char *refname = "test_read_format_7zip_encryption.7z";
	struct archive_entry *ae;
	struct archive *a;
	char buff[128];

	extract_reference_file(refname);
	assert((a = archive_read_new()) != NULL);
	assertEqualIntA(a, ARCHIVE_OK, archive_read_support_filter_all(a));
	assertEqualIntA(a, ARCHIVE_OK, archive_read_support_format_all(a));
	assertEqualIntA(a, ARCHIVE_OK, 
		archive_read_open_filename(a, refname, 10240));

	assertEqualIntA(a, ARCHIVE_READ_FORMAT_ENCRYPTION_DONT_KNOW, archive_read_has_encrypted_entries(a));

	/* Verify encrypted file "bar.txt". */
	assertEqualIntA(a, ARCHIVE_OK, archive_read_next_header(a, &ae));
	assertEqualInt((AE_IFREG | 0664), archive_entry_mode(ae));
	assertEqualString("bar.txt", archive_entry_pathname(ae));
	assertEqualInt(1379073980, archive_entry_mtime(ae));
	assertEqualInt(4, archive_entry_size(ae));
	assertEqualInt(1, archive_entry_is_data_encrypted(ae));
	assertEqualInt(0, archive_entry_is_metadata_encrypted(ae));
	assertEqualIntA(a, 1, archive_read_has_encrypted_entries(a));
	assertEqualInt(ARCHIVE_FAILED, archive_read_data(a, buff, sizeof(buff)));

	assertEqualInt(1, archive_file_count(a));

	/* End of archive. */
	assertEqualIntA(a, ARCHIVE_EOF, archive_read_next_header(a, &ae));

	/* Verify archive format. */
	assertEqualIntA(a, ARCHIVE_FILTER_NONE, archive_filter_code(a, 0));
	assertEqualIntA(a, ARCHIVE_FORMAT_7ZIP, archive_format(a));

	/* Close the archive. */
	assertEqualIntA(a, ARCHIVE_OK, archive_read_close(a));
	assertEqualInt(ARCHIVE_OK, archive_read_free(a));

	/* Test again with passphrase. */
	assert((a = archive_read_new()) != NULL);
	assertEqualIntA(a, ARCHIVE_OK, archive_read_support_filter_all(a));
	assertEqualIntA(a, ARCHIVE_OK, archive_read_support_format_all(a));
	assertEqualIntA(a, ARCHIVE_OK, archive_read_add_passphrase(a, "12345678"));
	assertEqualIntA(a, ARCHIVE_OK,
		archive_read_open_filename(a, refname, 10240));

	assertEqualIntA(a, ARCHIVE_READ_FORMAT_ENCRYPTION_DONT_KNOW, archive_read_has_encrypted_entries(a));

	/* Verify encrypted file "bar.txt" can be read with correct password. */
	assertEqualIntA(a, ARCHIVE_OK, archive_read_next_header(a, &ae));
	assertEqualInt((AE_IFREG | 0664), archive_entry_mode(ae));
	assertEqualString("bar.txt", archive_entry_pathname(ae));
	assertEqualInt(1379073980, archive_entry_mtime(ae));
	assertEqualInt(4, archive_entry_size(ae));
	assertEqualInt(1, archive_entry_is_data_encrypted(ae));
	assertEqualInt(0, archive_entry_is_metadata_encrypted(ae));
	assertEqualIntA(a, 1, archive_read_has_encrypted_entries(a));
	assertEqualInt(4, archive_read_data(a, buff, sizeof(buff)));
	assertEqualMem(buff, "foo\n", 4);

	/* End of archive. */
	assertEqualIntA(a, ARCHIVE_EOF, archive_read_next_header(a, &ae));

	/* Close the archive. */
	assertEqualIntA(a, ARCHIVE_OK, archive_read_close(a));
	assertEqualInt(ARCHIVE_OK, archive_read_free(a));

	/* Test with incorrect passphrase: reading data should fail. */
	assert((a = archive_read_new()) != NULL);
	assertEqualIntA(a, ARCHIVE_OK, archive_read_support_filter_all(a));
	assertEqualIntA(a, ARCHIVE_OK, archive_read_support_format_all(a));
	assertEqualIntA(a, ARCHIVE_OK, archive_read_add_passphrase(a, "wrongpassword"));
	assertEqualIntA(a, ARCHIVE_OK,
		archive_read_open_filename(a, refname, 10240));

	assertEqualIntA(a, ARCHIVE_OK, archive_read_next_header(a, &ae));
	assertEqualString("bar.txt", archive_entry_pathname(ae));
	/* Decrypting with wrong key produces corrupted stream that fails decompression. */
	assert(archive_read_data(a, buff, sizeof(buff)) < 0);

	assertEqualIntA(a, ARCHIVE_OK, archive_read_close(a));
	assertEqualInt(ARCHIVE_OK, archive_read_free(a));
}

static void
test_encryption_padding(const char *refname, int use_lzma)
{
	const size_t read_sizes[] = { 1, 15, 16, 17, 31, 10240 };
	const uint8_t key[32] = { 0 }, iv[16] = { 0 };
	archive_crypto_ctx ctx;
	struct archive_entry *ae;
	struct archive *a;
	char *archive_data;
	char buff[32];
	size_t archive_size, i;
	int r;

	memset(&ctx, 0, sizeof(ctx));
	r = archive_decrypto_aes_cbc_init(&ctx, key, sizeof(key),
	    iv, sizeof(iv));
	if (r == CRYPTOR_STUB_FUNCTION) {
		skipping("AES-CBC decryption is not supported");
		return;
	}
	if (!assertEqualInt(0, r))
		return;
	assertEqualInt(0, archive_decrypto_aes_cbc_release(&ctx));

	assert((a = archive_read_new()) != NULL);
	r = use_lzma ? archive_read_support_filter_lzma(a) :
	    archive_read_support_filter_gzip(a);
	assertEqualInt(ARCHIVE_OK, archive_read_free(a));
	if (r != ARCHIVE_OK) {
		skipping("Required compression library is not available");
		return;
	}

	/*
	 * 7zz 26.03: a -t7z -p12345678 -m0=LZMA2 (or Deflate)
	 *     -mhc=off -mtm=off -mta=off -mtc=off archive.7z data.bin
	 * data.bin contains "0123456789abcdef\n". Both codecs reach
	 * end-of-stream before consuming the final AES block's padding.
	 */
	extract_reference_file(refname);
	archive_data = slurpfile(&archive_size, "%s", refname);
	if (!assert(archive_data != NULL))
		return;
	for (i = 0; i < sizeof(read_sizes) / sizeof(read_sizes[0]); i++) {
		assert((a = archive_read_new()) != NULL);
		assertEqualIntA(a, ARCHIVE_OK, archive_read_support_filter_all(a));
		assertEqualIntA(a, ARCHIVE_OK, archive_read_support_format_7zip(a));
		assertEqualIntA(a, ARCHIVE_OK,
		    archive_read_add_passphrase(a, "12345678"));
		assertEqualIntA(a, ARCHIVE_OK, read_open_memory_seek(a,
		    archive_data, archive_size, read_sizes[i]));
		assertEqualIntA(a, ARCHIVE_OK, archive_read_next_header(a, &ae));
		assertEqualString("data.bin", archive_entry_pathname(ae));
		assertEqualInt(17, archive_entry_size(ae));
		assertEqualInt(1, archive_entry_is_data_encrypted(ae));
		failure("%s, read size %zu", refname, read_sizes[i]);
		if (assertEqualIntA(a, 17,
		    archive_read_data(a, buff, sizeof(buff)))) {
			assertEqualMem(buff, "0123456789abcdef\n", 17);
			assertEqualIntA(a, 0,
			    archive_read_data(a, buff, sizeof(buff)));
			assertEqualIntA(a, ARCHIVE_EOF,
			    archive_read_next_header(a, &ae));
		}
		assertEqualIntA(a, ARCHIVE_OK, archive_read_close(a));
		assertEqualInt(ARCHIVE_OK, archive_read_free(a));
	}
	free(archive_data);
}

DEFINE_TEST(test_read_format_7zip_encryption_padding_lzma2)
{
	test_encryption_padding(
	    "test_read_format_7zip_encryption_padding_lzma2.7z", 1);
}

DEFINE_TEST(test_read_format_7zip_encryption_padding_deflate)
{
	test_encryption_padding(
	    "test_read_format_7zip_encryption_padding_deflate.7z", 0);
}
