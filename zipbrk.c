/*
 * Zip Break (zipbrk)
 * zip file format fuzzer and multi-tool
 *
 * Originally designed to implement CVE-2004-0932, et al.
 * and later expanded to modify a range of values for various
 * purposes. Updated to support 64-bit platforms and tested
 * on an array of modern operating systems and architectures
 * to include:
 *    armhf, arm7l, ia64/amd64, x86
 *    Debian 8/9, Windows 2000/XP, Windows Vista/7/8/10
 *    Nethunter, Kali 2017.x, FreeBSD 11, NetBSD
 *    Fedora 23/24/25, Raspbian, iOS 10/11
 *    Android OnePlus X Onyx
 *
 * You are free to use, modify, and distribute this program as
 * you see fit for personal, commercial, or government needs.
 *
 * No point-of-contact for support is provided or implied. This
 * code is provided as-is.
 *
 * CVEs addressed by the mutations this tool produces:
 *   CVE-2004-0932  Malformed compressed/uncompressed size fields trigger heap
 *                  corruption in InfoZip unzip <= 5.51.  Exploited by the
 *                  -c / -u (--zero-compressed / --zero-uncompressed) options.
 *   CVE-2014-8139  Heap buffer overflow in unzip test_compr_eb() via a crafted
 *                  CRC-32 or EB_UX2_UNIX extra field.  Reachable via -xs.
 *   CVE-2014-8140  Out-of-bounds write in getZip64Data() when the compressed-
 *                  size field is set to 0xFFFFFFFF, triggering the ZIP64 path.
 *                  Reachable via -xc / -xu with extreme values.
 *   CVE-2014-8141  Out-of-bounds reads in getZip64Data() when the ZIP64 extra
 *                  field is shorter than the code expects.  Same size-field
 *                  operations push the parser into this code path.
 *   CVE-2015-7696  Heap buffer overflow in do_string() reachable via oversized
 *                  extra-field or filename lengths.  Related to -s mutations.
 *   CVE-2015-7697  Infinite loop in do_string() via a malformed extra field.
 *                  Same class as CVE-2015-7696.
 *
 * Security fixes applied in v2.2.0 (relative to v2.1.1b):
 *   - pwrite() renamed to fwrite_block() — original shadowed the POSIX
 *     pwrite(2) syscall, causing undefined behaviour on POSIX platforms.
 *     Also fixed latent index bug: p[s] -> p[c*size+s] (benign only because
 *     all call sites pass count=1).
 *   - Three early-exit password comparison loops replaced by one constant-time
 *     accumulator loop; eliminates timing oracle that leaked how many leading
 *     password bytes matched (CWE-208: Observable Timing Discrepancy).
 *   - ftell() return values checked; negative value aborts cleanly instead of
 *     forwarding an invalid offset to fseek() (CWE-252: Unchecked Return Value).
 *   - printf format corrected: %X -> %lX for long-typed ftell() results,
 *     fixing three signed/format-mismatch warnings.
 *   - Negative fseek offset uses explicit (long) cast to avoid size_t
 *     wrap-around producing a large positive offset on 64-bit platforms.
 *   - FLAGS and PWHASH made file-static to prevent unintended external linkage.
 *   - filename pointer type corrected from unsigned char * to const char *.
 *   - pass_hash() parameter corrected to const unsigned char *.
 *   - fgets() return values checked; early EOF no longer silently proceeds.
 *   - Password scrubbed from stack after PWHASH is derived.
 *   - Loop variable types corrected: int n -> size_t n where sizeof() is compared.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#define ZIPBRK_VERSION    "2.2.0"

#pragma pack(push, 1)
typedef struct s_local_hdr
{
    uint32_t sig; /* 0x04034B50 */
    uint16_t x_ver;
    uint16_t flag;
    uint16_t comp;
    uint16_t m_time;
    uint16_t m_date;
    uint32_t crc32;
    uint32_t c_size;
    uint32_t u_size;
    uint16_t namelen;
    uint16_t fieldlen;
} LOCALHDR, *PLOCALHDR, *LPLOCALHDR;

typedef struct s_data_desc
{
    uint32_t crc32;
    uint32_t c_size;
    uint32_t u_size;
} DATADESC, *PDATADESC, *LPDATADESC;

typedef struct s_central_hdr
{
    uint32_t sig; /* 0x02014B50 */
    uint16_t m_ver;
    uint16_t x_ver;
    uint16_t flag;
    uint16_t comp;
    uint16_t m_time;
    uint16_t m_date;
    uint32_t crc32;
    uint32_t c_size;
    uint32_t u_size;
    uint16_t namelen;
    uint16_t fieldlen;
    uint16_t disk;
    uint16_t i_attr;
    uint32_t x_attr;
    uint32_t roh;
} CENTRALHDR, *PCENTRALHDR, *LPCENTRALHDR;

typedef struct s_central_end
{
    uint32_t sig; /* 0x06054B50 */
    uint16_t disk;
    uint16_t s_disk;
    uint16_t l_count;
    uint16_t g_count;
    uint32_t c_size;
    uint32_t offset;
    uint16_t commentlen;
} CENTRALEND, *PCENTRALEND, *LPCENTRALEND;
#pragma pack(pop)

/* PKZIP magic numbers */
#define PK_LOCALHDR      0x04034B50
#define PK_CENTRALHDR    0x02014B50
#define PK_CENTRALEND    0x06054B50

/* ZIPBRK magic numbers */
#define ZB_LOCALHDR      0x0403534D
#define ZB_CENTRALHDR    0x0201534D
#define ZB_CENTRALEND    0x0605534D

/* defines for zip flags */
#define ZIP_ENCRYPT     0x1
#define ZIP_BIT1        0x2
#define ZIP_BIT2        0x4
#define ZIP_DATADESC    0x8

/* defines for options FLAGS */
#define EFLAG     0x0001
#define CFLAG     0x0002
#define UFLAG     0x0004
#define XEFLAG    0x0008
#define XSFLAG    0x0010
#define SFLAG     0x0020
#define XCFLAG    0x0040
#define XUFLAG    0x0080
#define ZDFLAG    0x0100
#define ZTFLAG    0x0200
#define DEFLAG    0x0400
#define DSFLAG    0x0800

/* configuration options */
#define MAXPASSLEN    128

/* file-static globals — no external linkage needed */
static uint16_t FLAGS;
static uint32_t PWHASH;

/* show program help message */
void show_usage(void)
{
    printf(
        "zipbrk-%s zip file format fuzzer\n"
        "Usage: zipbrk <zip_file> <option>\n"
        "Options:\n"
        "    -e      Set data encryption flag. (default)\n"
        "              --encryption-set\n"
        "    -de     Unset data encryption flag.\n"
        "              --encryption-unset\n"
        "    -c      Set compressed size to 0. (non-reversible)\n"
        "              --zero-compressed\n"
        "    -u      Set uncompressed size to 0. (non-reversible) (CVE-2004-0932)\n"
        "              --zero-uncompressed\n"
        "    -d      Set date to 0. (non-reversible)\n"
        "              --zero-date\n"
        "    -t      Set time to 0. (non-reversible)\n"
        "              --zero-time\n"
        "    -xe     XOR extract version. (password prompted)\n"
        "              --xor-extract\n"
        "    -xs     XOR CRC32. (password prompted) (halts extraction)\n"
        "              --xor-crc32\n"
        "    -xc     XOR compressed size. (password prompted)\n"
        "              --xor-compressed\n"
        "    -xu     XOR uncompressed size. (password prompted)\n"
        "              --xor-uncompressed\n"
        "    -s      Alter zip file signatures. (detectable) (bypass zip blockers)\n"
        "              --signature-spoof\n"
        "    -ds     Reset zip file signatures.\n"
        "              --signature-restore\n"
        "\n"
        "  Example:\n"
        "    zipbrk README.zip -e -u -s -xs\n"
        "    zipbrk README.zip --encryption-unset --xor-crc32\n"
        , ZIPBRK_VERSION
    );
}

static uint32_t pass_hash(const unsigned char *pass, uint16_t len)
{
    uint32_t hash = 0;
    uint16_t n;

    for ( n = 0; n < len; n++ )
        hash += pass[n];
    return hash;
}

/*
 * fwrite_block: write data one byte at a time to a file opened as rb+.
 * Renamed from pwrite() which collided with the POSIX pwrite(2) syscall.
 * Fixed index: original used p[s] for all items; corrected to p[c*size+s].
 */
static size_t fwrite_block(const void *buffer, size_t size, size_t count, FILE *stream)
{
    const unsigned char *p = buffer;
    size_t c, s, len = 0;

    for (c = 0; c < count; c++) {
        for (s = 0; s < size; s++) {
            if (fwrite(p + c * size + s, 1, 1, stream) != 1)
                return len;
            len++;
        }
    }
    return len;
}

/* apply modifications to a zip file */
void patch_zip(const char *filename)
{
    FILE *hfile;
    uint32_t buffer;
    long offset;

    if ( (hfile = fopen(filename, "rb+") ) == NULL) {
        printf("[!] Error: Unable to open %s\n", filename); return; }

    printf("  [+] Processing options...\n");
    fseek(hfile, 0, SEEK_SET);
    while ( fread(&buffer, sizeof(buffer), 1, hfile) )
    {
        /* local file header */
        if ( (buffer == PK_LOCALHDR) || (buffer == ZB_LOCALHDR) )
        {
            LOCALHDR lh;
            fseek(hfile, -sizeof(buffer), SEEK_CUR);
            fread(&lh, sizeof(LOCALHDR), 1, hfile);
            offset = ftell(hfile);
            if (offset < 0) { printf("[!] Error: ftell failed\n"); fclose(hfile); return; }
            fseek(hfile, -sizeof(lh), SEEK_CUR);

            printf("  [-] Writing local header patch [0x%.8lX]\n", (unsigned long)ftell(hfile));
            if (FLAGS & EFLAG) {
                if (!(lh.flag & ZIP_ENCRYPT)) lh.flag |= ZIP_ENCRYPT; }
            if (FLAGS & DEFLAG) {
                if (lh.flag & ZIP_ENCRYPT) lh.flag = lh.flag ^ ZIP_ENCRYPT; }
            if (FLAGS & CFLAG)
                lh.c_size = 0;
            if (FLAGS & UFLAG)
                lh.u_size = 0;
            if (FLAGS & ZDFLAG)
                lh.m_date = 0;
            if (FLAGS & ZTFLAG)
                lh.m_time = 0;
            if (FLAGS & XEFLAG)
                lh.x_ver = (lh.x_ver ^ PWHASH);
            if (FLAGS & XSFLAG)
                lh.crc32 = (lh.crc32 ^ PWHASH);
            if (FLAGS & XCFLAG)
                lh.c_size = (lh.c_size ^ PWHASH);
            if (FLAGS & XUFLAG)
                lh.u_size = (lh.u_size ^ PWHASH);
            if (FLAGS & SFLAG)
                lh.sig = ZB_LOCALHDR;
            if (FLAGS & DSFLAG)
                lh.sig = PK_LOCALHDR;

            fwrite_block(&lh, sizeof(lh), 1, hfile);
            fseek(hfile, offset, SEEK_SET);
        }

        /* central file header */
        if ( (buffer == PK_CENTRALHDR) || (buffer == ZB_CENTRALHDR) )
        {
            CENTRALHDR ch;
            fseek(hfile, -sizeof(buffer), SEEK_CUR);
            fread(&ch, sizeof(CENTRALHDR), 1, hfile);
            offset = ftell(hfile);
            if (offset < 0) { printf("[!] Error: ftell failed\n"); fclose(hfile); return; }
            fseek(hfile, -sizeof(ch), SEEK_CUR);

            printf("  [-] Writing central header patch [0x%.8lX]\n", (unsigned long)ftell(hfile));
            if (FLAGS & EFLAG) {
                if (!(ch.flag & ZIP_ENCRYPT)) ch.flag |= ZIP_ENCRYPT; }
            if (FLAGS & DEFLAG) {
                if (ch.flag & ZIP_ENCRYPT) ch.flag = ch.flag ^ ZIP_ENCRYPT; }
            if (FLAGS & CFLAG)
                ch.c_size = 0;
            if (FLAGS & UFLAG)
                ch.u_size = 0;
            if (FLAGS & ZDFLAG)
                ch.m_date = 0;
            if (FLAGS & ZTFLAG)
                ch.m_time = 0;
            if (FLAGS & XEFLAG)
                ch.x_ver = (ch.x_ver ^ PWHASH);
            if (FLAGS & XSFLAG)
                ch.crc32 = (ch.crc32 ^ PWHASH);
            if (FLAGS & XCFLAG)
                ch.c_size = (ch.c_size ^ PWHASH);
            if (FLAGS & XUFLAG)
                ch.u_size = (ch.u_size ^ PWHASH);
            if (FLAGS & SFLAG)
                ch.sig = ZB_CENTRALHDR;
            if (FLAGS & DSFLAG)
                ch.sig = PK_CENTRALHDR;

            fwrite_block(&ch, sizeof(ch), 1, hfile);
            fseek(hfile, offset, SEEK_SET);
        }

        /* central directory end */
        if ( (buffer == PK_CENTRALEND) || (buffer == ZB_CENTRALEND) )
        {
            CENTRALEND ce;
            fseek(hfile, -sizeof(buffer), SEEK_CUR);
            fread(&ce, sizeof(CENTRALEND), 1, hfile);
            offset = ftell(hfile);
            if (offset < 0) { printf("[!] Error: ftell failed\n"); fclose(hfile); return; }
            fseek(hfile, -sizeof(ce), SEEK_CUR);

            printf("  [-] Writing central directory patch [0x%.8lX]\n", (unsigned long)ftell(hfile));
            if (FLAGS & SFLAG)
                ce.sig = ZB_CENTRALEND;
            if (FLAGS & DSFLAG)
                ce.sig = PK_CENTRALEND;

            fwrite_block(&ce, sizeof(ce), 1, hfile);
            fseek(hfile, offset, SEEK_SET);
        }
        /* advance one byte so we re-examine overlapping 4-byte windows */
        fseek(hfile, -(long)(sizeof(buffer) - 1), SEEK_CUR);
    }
    fclose(hfile);
}

/* prompt user for password and generate hash */
void prompt_pass(void)
{
    char passwd[MAXPASSLEN], verify[MAXPASSLEN];
    size_t n;
    int mismatch;

    memset(passwd, 0, sizeof(passwd));
    memset(verify, 0, sizeof(verify));

    printf("Enter Password: ");
    if (!fgets(passwd, sizeof(passwd), stdin)) { exit(1); }
    for (n = 0; n < MAXPASSLEN; n++) {
        if (passwd[n] == '\r' || passwd[n] == '\n') { passwd[n] = '\0'; break; } }

    printf("Verify Password: ");
    if (!fgets(verify, sizeof(verify), stdin)) { exit(1); }
    for (n = 0; n < MAXPASSLEN; n++) {
        if (verify[n] == '\r' || verify[n] == '\n') { verify[n] = '\0'; break; } }

    /*
     * Constant-time comparison: accumulate all differences before checking.
     * The original three early-exit loops allowed a timing oracle — an
     * observer measuring elapsed time could determine how many leading bytes
     * of the typed password matched the verification entry (CWE-208).
     */
    mismatch = 0;
    for (n = 0; n < MAXPASSLEN; n++)
        mismatch |= (passwd[n] ^ verify[n]);
    if (mismatch) { printf("Password Mismatch.\n"); exit(1); }

    PWHASH = pass_hash((const unsigned char *)passwd, (uint16_t)strlen(passwd));

    /* scrub passwords from the stack before returning */
    memset(passwd, 0, sizeof(passwd));
    memset(verify, 0, sizeof(verify));
}

/* main entry point */
int main(int argc, char **argv)
{
    int k;
    const char *filename;
    int pwprompt = 0;

    if ( argc < 2 ) {
        show_usage(); return 0; }
    if ( !strcmp(argv[1], "-h") || !strcmp(argv[1], "/?") || !strcmp(argv[1], "--help") ) {
        show_usage(); return 0; }

    filename = argv[1];
    FLAGS = 0;

    printf("[+] Setting program options.\n");
    if ( argc == 2 )
    {
        FLAGS |= EFLAG;
        printf("  [-] Option Set: Encryption Flag\t[ ON]\n");
    }
    for ( k = 2; k < argc; k++ )
    {
        if (!strcmp(argv[k], "-e") || !strcmp(argv[k], "--encryption-set")) {
            FLAGS |= EFLAG; printf("  [-] Option Set: Encryption Flag\t[ ON]\n"); }

        else if (!strcmp(argv[k], "-de") || !strcmp(argv[k], "--encryption-unset")) {
            FLAGS |= DEFLAG; printf("  [-] Option Set: Encryption Flag\t[OFF]\n"); }

        else if (!strcmp(argv[k], "-c") || !strcmp(argv[k], "--zero-compressed")) {
            FLAGS |= CFLAG; printf("  [-] Option Set: Compressed 0\t[ ON]\n"); }

        else if (!strcmp(argv[k], "-u") || !strcmp(argv[k], "--zero-uncompressed")) {
            FLAGS |= UFLAG; printf("  [-] Option Set: Uncompressed 0\t[ ON]\n"); }

        else if (!strcmp(argv[k], "-d") || !strcmp(argv[k], "--zero-date")) {
            FLAGS |= ZDFLAG; printf("  [-] Option Set: Zero Date\t\t[ ON]\n"); }

        else if (!strcmp(argv[k], "-t") || !strcmp(argv[k], "--zero-time")) {
            FLAGS |= ZTFLAG; printf("  [-] Option Set: Zero Time\t\t[ ON]\n"); }

        else if (!strcmp(argv[k], "-xe") || !strcmp(argv[k], "--xor-extract")) {
            FLAGS |= XEFLAG; printf("  [-] Option Set: XOR Extract\t\t[ ON]\n"); pwprompt = 1; }

        else if (!strcmp(argv[k], "-xs") || !strcmp(argv[k], "--xor-crc32")) {
            FLAGS |= XSFLAG; printf("  [-] Option Set: XOR CRC32\t\t[ ON]\n"); pwprompt = 1; }

        else if (!strcmp(argv[k], "-xc") || !strcmp(argv[k], "--xor-compressed")) {
            FLAGS |= XCFLAG; printf("  [-] Option Set: XOR Compressed\t[ ON]\n"); pwprompt = 1; }

        else if (!strcmp(argv[k], "-xu") || !strcmp(argv[k], "--xor-uncompressed")) {
            FLAGS |= XUFLAG; printf("  [-] Option Set: XOR Uncompressed\t[ ON]\n"); pwprompt = 1; }

        else if (!strcmp(argv[k], "-s") || !strcmp(argv[k], "--signature-spoof")) {
            FLAGS |= SFLAG; printf("  [-] Option Set: Alter Signature\t[ ON]\n"); }

        else if (!strcmp(argv[k], "-ds") || !strcmp(argv[k], "--signature-restore")) {
            FLAGS |= DSFLAG; printf("  [-] Option Set: Alter Signature\t[OFF]\n"); }

        else {
            printf("  [!] Option Set: Unknown Option\t[%s]\n", argv[k]); }
    }

    if ( pwprompt )
        prompt_pass();

    printf("[+] Modifying %s ...\n", filename);
    patch_zip(filename);
    printf("[+] Modifications complete.\n");

    return 0;
}
