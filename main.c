/*
 *  This file is based on code from Amit Singh, published here:
 *  http://osxbook.com/book/bonus/chapter7/tpmdrmmyth/
 *  Copyright (c) 2008 Amit Singh. All Rights Reserved.
 *
 *  This implementation copyright (c) 2009 Jim Dovey.
 */

#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <sysexits.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <copyfile.h>

#include <mach/mach.h>
#include <mach/machine.h>

#include <mach-o/fat.h>
#include <mach-o/loader.h>

#include <openssl/aes.h>

#include <IOKit/IOKitLib.h>

#define APB_UNPROTECTED_HEADER_SIZE		(3 * PAGE_SIZE)
#define APB_CRYPT_AES_KEY_SIZE			(256)
#define APB_FAT_MAX_ARCH				(5)

#define EX_TEXTTOOSMALL                 (EX__MAX + 1)

#if defined(__GNUC__) && !defined(__STRICT_ANSI__)
# ifndef MIN
#  define MIN(A,B)	({ __typeof__(A) __a = (A); __typeof__(B) __b = (B); __a < __b ? __a : __b; })
# endif
#else
# ifndef MIN
#  define MIN(A,B)	((A) < (B) ? (A) : (B))
# endif
#endif

static char header_page[PAGE_SIZE];
static char arch_page[PAGE_SIZE];
static char data_page[PAGE_SIZE];
static char xcrypted_page[PAGE_SIZE];

int fd_in = -1;
int fd_out = -1;

static boolean_t apb_set_key( int mode, uint8_t * data, AES_KEY * key );
static boolean_t apb_initialize( int mode, AES_KEY * key1, AES_KEY * key2 );
static int apb_encrypt_page( int mode, const void * src, void * dst );

static io_connect_t AppleSMC_Connect( void );
static void AppleSMC_Disconnect( io_connect_t smc );
static IOReturn AppleSMC_Read32( io_connect_t smc, uint32_t key, uint8_t *pData );

typedef struct
{
    uint32_t    key;
    uint8_t     __d0[22];
    uint32_t    datasize;
    uint8_t     __d1[10];
    uint8_t     cmd;
    uint32_t    __d2;
    uint8_t     data[32];
    
} AppleSMCBuffer_t;

#pragma mark -

static io_connect_t AppleSMC_Connect( void )
{
    io_connect_t port = (io_connect_t)0;
    
    io_service_t service = IOServiceGetMatchingService( kIOMasterPortDefault, IOServiceMatching("AppleSMC") );
    if ( service == 0 )
        return ( 0 );
    
    kern_return_t kr = IOServiceOpen( service, mach_task_self(), 0, &port );
    IOObjectRelease( service );
    
    if ( kr != kIOReturnSuccess )
        return ( 0 );
    
    return ( port );
}

static void AppleSMC_Disconnect( io_connect_t smc )
{
    (void) IOServiceClose( smc );
}

static IOReturn AppleSMC_Read32( io_connect_t smc, uint32_t key, uint8_t * data32 )
{
    AppleSMCBuffer_t input = { 0, {0}, 32, {0}, 5, };
    AppleSMCBuffer_t output;
    size_t outputSize = sizeof(AppleSMCBuffer_t);
    
    input.key = key;
    
    IOReturn kr = IOConnectCallStructMethod( (mach_port_t)smc, 2, (const void *)&input,
                                             sizeof(AppleSMCBuffer_t), (void *)&output, &outputSize );
    if ( kr != kIOReturnSuccess )
        return ( kr );
    
    (void) memcpy( data32, output.data, 32 );
    return ( kIOReturnSuccess );
}

#pragma mark -

static boolean_t apb_set_key( int mode, uint8_t * data, AES_KEY * key )
{
    switch ( mode )
    {
        case AES_ENCRYPT:
            AES_set_encrypt_key( data, APB_CRYPT_AES_KEY_SIZE, key );
            break;
            
        case AES_DECRYPT:
            AES_set_decrypt_key( data, APB_CRYPT_AES_KEY_SIZE, key );
            break;
            
        default:
            return ( FALSE );
            break;
    }
    
    return ( TRUE );
}

static boolean_t apb_initialize( int mode, AES_KEY * key1, AES_KEY * key2 )
{
    boolean_t result = FALSE;
    
    io_connect_t smc = AppleSMC_Connect();
    if ( smc == 0 )
        return ( FALSE );
    
    do
    {
        IOReturn ret;
        uint8_t data32[32] = { 0 };
        
        ret = AppleSMC_Read32( smc, 'OSK0', data32 );
        if ( ret != kIOReturnSuccess )
            break;
        
        if ( apb_set_key(mode, data32, key1) == FALSE )
            break;
        
        ret = AppleSMC_Read32( smc, 'OSK1', data32 );
        if ( ret != kIOReturnSuccess )
            break;
        
        if ( apb_set_key(mode, data32, key2) == FALSE )
            break;
        
        result = TRUE;
    
    } while (0);
    
    AppleSMC_Disconnect( smc );
    return ( result );
}

static int apb_encrypt_page( int mode, const void * src, void * dst )
{
    static AES_KEY key1, key2;
    static boolean_t initialized = FALSE;
    
    if ( initialized == FALSE )
    {
        initialized = apb_initialize( mode, &key1, &key2 );
        if ( initialized == FALSE )
            return ( -1 );
    }
    
    const unsigned char * in = (const unsigned char *) src;
    unsigned char * out = (unsigned char *) dst;
    
    unsigned char apb_null_iv1[AES_BLOCK_SIZE] = { 0 };
    unsigned char apb_null_iv2[AES_BLOCK_SIZE] = { 0 };
    
    AES_cbc_encrypt( in, out, PAGE_SIZE >> 1, &key1, apb_null_iv1, mode );
    in += (PAGE_SIZE >> 1);
    out += (PAGE_SIZE >> 1);
    AES_cbc_encrypt( in, out, PAGE_SIZE >> 1, &key2, apb_null_iv2, mode );
    
    return ( 0 );
}

static int crypt_text_segment( int mode, off_t base, off_t fileoff, off_t filesize )
{
    off_t archbase_begin = (off_t)(fileoff + APB_UNPROTECTED_HEADER_SIZE);
    off_t archbase_end = archbase_begin + (off_t)(filesize - APB_UNPROTECTED_HEADER_SIZE);
    
    off_t ebase_begin = base + archbase_begin;
    off_t ebase_end = base + archbase_end;
    
    off_t count = ebase_end - ebase_begin;
    if ( (count % PAGE_SIZE) != 0 )
    {
        fprintf( stderr, "text segment is not a multiple of page size.\n" );
        return ( EX_SOFTWARE );
    }
    
    while ( count > 0 )
    {
        ssize_t nbytes = pread( fd_in, data_page, PAGE_SIZE, ebase_begin );
        if ( nbytes != PAGE_SIZE )
        {
            perror( "pread" );
            return ( EX_IOERR );
        }
        
        int err = apb_encrypt_page( mode, data_page, xcrypted_page );
        if ( err != 0 )
        {
            fprintf( stderr, "failed to %s page.\n", (mode == AES_ENCRYPT ? "encrypt" : "decrypt") );
            return ( EX_SOFTWARE );
        }
        
        nbytes = pwrite( fd_out, xcrypted_page, PAGE_SIZE, ebase_begin );
        if ( nbytes != PAGE_SIZE )
        {
            perror( "pwrite" );
            return ( EX_IOERR );
        }
        
        ebase_begin += (off_t)PAGE_SIZE;
        count -= (off_t)PAGE_SIZE;
    }
    
    return ( EX_OK );
}

static int crypt_binary_64( const struct mach_header_64 * mh, off_t base )
{
    int mode = AES_ENCRYPT;
    struct segment_command_64 * text = (struct segment_command_64 *)0;
    
    uint32_t ncmds = mh->ncmds;
    struct load_command * lc = (struct load_command *)((char *)mh + sizeof(struct mach_header_64));
    
    uint32_t n;
    for ( n = 0; n < ncmds; n++ )
    {
        if ( lc->cmd == LC_SEGMENT_64 )
        {
            struct segment_command_64 * sc = (struct segment_command_64 *) lc;
            if ( strncmp(sc->segname, SEG_TEXT, 16) == 0 )
            {
                text = sc;
                break;
            }
        }
        
        lc = (struct load_command *)((char *)lc + lc->cmdsize);
    }
    
    if ( text == NULL )
    {
        fprintf( stderr, "failed to find text segment.\n" );
        return ( EX_SOFTWARE );
    }
    
    if ( (text->flags & SG_PROTECTED_VERSION_1) == SG_PROTECTED_VERSION_1 )
    {
        mode = AES_DECRYPT;
        fprintf( stdout, "binary is encrypted - will decrypt it.\n" );
    }
    else if ( text->filesize < APB_UNPROTECTED_HEADER_SIZE )
    {
        fprintf( stderr, "text segment is too small to protect\n" );
        return ( EX_TEXTTOOSMALL );
    }
    
    if ( mode == AES_ENCRYPT )
        text->flags |= SG_PROTECTED_VERSION_1;
    else
        text->flags &= ~SG_PROTECTED_VERSION_1;
    
    ssize_t nbytes = pwrite( fd_out, arch_page, PAGE_SIZE, base );
    if ( nbytes != PAGE_SIZE )
    {
        perror( "pwrite" );
        return ( EX_IOERR );
    }
    
    return ( crypt_text_segment(mode, base, (off_t)text->fileoff, (off_t)text->filesize) );
}

static int crypt_binary( const struct mach_header * mh, off_t base )
{
    int mode = AES_ENCRYPT;
    struct segment_command * text = (struct segment_command *)0;
    
    uint32_t ncmds = mh->ncmds;
    struct load_command * lc = (struct load_command *)((char *)mh + sizeof(struct mach_header));
    
    uint32_t n;
    for ( n = 0; n < ncmds; n++ )
    {
        if ( lc->cmd == LC_SEGMENT )
        {
            struct segment_command * sc = (struct segment_command *) lc;
            if ( strncmp(sc->segname, SEG_TEXT, 16) == 0 )
            {
                text = sc;
                break;
            }
        }
        
        lc = (struct load_command *)((char *)lc + lc->cmdsize);
    }
    
    if ( text == NULL )
    {
        fprintf( stderr, "failed to find text segment.\n" );
        return ( EX_SOFTWARE );
    }
    
    if ( (text->flags & SG_PROTECTED_VERSION_1) == SG_PROTECTED_VERSION_1 )
    {
        mode = AES_DECRYPT;
        fprintf( stdout, "binary is encrypted - will decrypt it.\n" );
    }
    else if ( text->filesize < APB_UNPROTECTED_HEADER_SIZE )
    {
        fprintf( stderr, "text segment is too small to protect\n" );
        return ( EX_TEXTTOOSMALL );
    }
    
    if ( mode == AES_ENCRYPT )
        text->flags |= SG_PROTECTED_VERSION_1;
    else
        text->flags &= ~SG_PROTECTED_VERSION_1;
    
    ssize_t nbytes = pwrite( fd_out, arch_page, PAGE_SIZE, base );
    if ( nbytes != PAGE_SIZE )
    {
        perror( "pwrite" );
        return ( EX_IOERR );
    }
    
    return ( crypt_text_segment(mode, base, (off_t)text->fileoff, (off_t)text->filesize) );
}

int main( int argc, char * const argv[] )
{
    if ( argc != 3 )
    {
        fprintf( stderr, "usage: %s <infile> <outfile>\n", argv[0] );
        exit( EX_USAGE );
    }
    
    int ret = 0;
    
    fd_in = open( argv[1], O_RDONLY );
    if ( fd_in < 0 )
    {
        perror( "open" );
        exit( EX_IOERR );
    }
    
    fd_out = open( argv[2], O_RDWR | O_CREAT | O_EXCL, 0775 );
    if ( fd_out < 0 )
    {
        perror( "open" );
        ret = EX_IOERR;
        goto out;
    }
    
    // I copy the file earlier, so I can encrypt multiple text segments
    //  in a fat binary
    ret = fcopyfile( fd_in, fd_out, (copyfile_state_t)0, COPYFILE_ALL );
    if ( ret != 0 )
    {
        perror( "copyfile" );
        ret = EX_OSERR;
        goto out;
    }
    
    off_t base = 0;
    uint32_t n = 0;
    
    ssize_t nbytes = pread( fd_in, header_page, PAGE_SIZE, (off_t)0 );
    if ( nbytes != PAGE_SIZE )
    {
        perror( "pread" );
        ret = EX_IOERR;
        goto out;
    }
    
    uint32_t magic = *(uint32_t *) header_page;
    struct mach_header * mh = (struct mach_header *) NULL;
    
#if defined(__ppc__) || defined(__ppc64__)
# error This code won't compile for PPC, where encrypted binaries are not supported.
#endif
    if ( magic == FAT_CIGAM )
    {
        // byte-swapped FAT header
        struct fat_header * fh = (struct fat_header *) header_page;
        uint32_t nfat_arch = OSSwapConstInt32( fh->nfat_arch );
        if ( nfat_arch > APB_FAT_MAX_ARCH )
        {
            fprintf( stderr, "too many architectures in Universal binary.\n" );
            ret = EX_SOFTWARE;
            goto out;
        }
        
        struct fat_arch * fa = (struct fat_arch *)((char *)header_page + sizeof(struct fat_header));
        for ( n = 0; n < nfat_arch; n++, fa++ )
        {
            // match against either i386 or x86-64
            cpu_type_t cputype = OSSwapConstInt32(fa->cputype);
            if ( (cputype & ~CPU_ARCH_MASK) == CPU_TYPE_X86 )
            {
                base = (off_t) OSSwapConstInt32(fa->offset);
                nbytes = pread( fd_in, arch_page, PAGE_SIZE, base );
                if ( nbytes != PAGE_SIZE )
                {
                    fprintf( stderr, "failed to read Universal binary.\n" );
                    ret = EX_IOERR;
                    goto out;
                }
                
                int subret;
                if ( (cputype & CPU_ARCH_ABI64) == CPU_ARCH_ABI64 )
                    subret = crypt_binary_64( (struct mach_header_64 *)arch_page, base );
                else
                    subret = crypt_binary( (struct mach_header *)arch_page, base );
                
                if ( (ret != EX_OK) && (ret != EX_TEXTTOOSMALL) )
                {
                    ret = subret;
                    break;
                }
                
                ret = MIN(ret, subret);
            }
        }
    }
    else if ( magic == MH_MAGIC )
    {
        memcpy( arch_page, header_page, PAGE_SIZE );
        mh = (struct mach_header *) arch_page;
        if ( (mh->cputype & ~CPU_ARCH_MASK) != CPU_TYPE_X86 )
        {
            fprintf( stderr, "this program only supports x86 or x86-64 architectures.\n" );
            ret = EX_USAGE;
            goto out;
        }
        
        ret = crypt_binary( mh, 0 );
    }
    else
    {
        fprintf( stderr, "not an appropriate Mach-O file.\n" );
        ret = EX_USAGE;
        goto out;
    }
    
out:
    if ( fd_in >= 0 )
        close( fd_in );
    if ( fd_out >= 0 )
    {
        close( fd_out );
        if ( ret != EX_OK )
            unlink( argv[2] );
    }
    
    return ( ret );
}
