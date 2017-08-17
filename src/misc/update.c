/*****************************************************************************
 * update.c: VLC update checking and downloading
 *****************************************************************************
 * Copyright © 2005-2008 VLC authors and VideoLAN
 * $Id$
 *
 * Authors: Antoine Cellerier <dionoea -at- videolan -dot- org>
 *          Rémi Duraffort <ivoire at via.ecp.fr>
            Rafaël Carré <funman@videolanorg>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either release 2 of the License, or
 * (at your option) any later release.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston MA 02110-1301, USA.
 *****************************************************************************/

/**
 *   \file
 *   This file contains functions related to VLC update management
 */

/*****************************************************************************
 * Preamble
 *****************************************************************************/

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <vlc_common.h>
#include <vlc_update.h>

#include <assert.h>

#include <vlc_pgpkey.h>
#include <vlc_stream.h>
#include <vlc_strings.h>
#include <vlc_fs.h>
#include <vlc_dialog.h>
#include <vlc_interface.h>

#include <gcrypt.h>
#include <vlc_gcrypt.h>
#ifdef _WIN32
#include <shellapi.h>
#endif
#include "update.h"
#include "../libvlc.h"
#include "../../modules/misc/webservices/json.h"

/*****************************************************************************
 * Misc defines
 *****************************************************************************/

/*
 * Here is the format of these "status files" :
 * First line is the last version: "X.Y.Z.E" where:
 *      * X is the major number
 *      * Y is the minor number
 *      * Z is the revision number
 *      * .E is an OPTIONAL extra number
 *      * IE "1.2.0" or "1.1.10.1"
 * Second line is a url of the binary for this last version
 * Remaining text is a required description of the update
 */

#define BUILD_CHANNEL "stable" 

#if defined( _WIN64 )
# define UPDATE_OS_SUFFIX "-win-x64"
#elif defined( _WIN32 )
# define UPDATE_OS_SUFFIX "-win-x86"
#else
# define UPDATE_OS_SUFFIX ""
#endif

#ifndef NDEBUG
# define UPDATE_VLC_STATUS_URL "http://update-test.videolan.org/vlc/status-win-x86"
#else
// to be modified
# define UPDATE_VLC_STATUS_URL "http://update.videolan.org/vlc/" BUILD_CHANNEL "/status" UPDATE_OS_SUFFIX
#endif

#define dialog_FatalWait( p_obj, psz_title, psz_fmt, ... ) \
    vlc_dialog_wait_question( p_obj, VLC_DIALOG_QUESTION_CRITICAL, "OK", NULL, \
                              NULL, psz_title, psz_fmt, ##__VA_ARGS__ );

/*****************************************************************************
 * Update_t functions
 *****************************************************************************/

#undef update_New
/**
 * Create a new update VLC struct
 *
 * \param p_this the calling vlc_object
 * \return pointer to new update_t or NULL
 */
update_t *update_New( vlc_object_t *p_this )
{
    update_t *p_update;
    assert( p_this );

    p_update = (update_t *)malloc( sizeof( update_t ) );
    if( !p_update ) return NULL;

    vlc_mutex_init( &p_update->lock );

    p_update->p_libvlc = p_this->obj.libvlc;

    p_update->release.psz_url = NULL;
    p_update->release.psz_desc = NULL;

    p_update->p_download = NULL;
    p_update->p_check = NULL;

    p_update->p_pkey = NULL;
    vlc_gcrypt_init();

    return p_update;
}

/**
 * Delete an update_t struct
 *
 * \param p_update update_t* pointer
 * \return nothing
 */
void update_Delete( update_t *p_update )
{
    assert( p_update );

    if( p_update->p_check )
    {
        vlc_join( p_update->p_check->thread, NULL );
        free( p_update->p_check );
    }

    if( p_update->p_download )
    {
        atomic_store( &p_update->p_download->aborted, true );
        vlc_join( p_update->p_download->thread, NULL );
        vlc_object_release( p_update->p_download );
    }

    vlc_mutex_destroy( &p_update->lock );

    free( p_update->release.psz_url );
    free( p_update->release.psz_desc );
    free( p_update->p_pkey );

    free( p_update );
}

/**
 * Empty the release struct
 *
 * \param p_update update_t* pointer
 * \return nothing
 */
static void EmptyRelease( update_t *p_update )
{
    p_update->release.i_major = 0;
    p_update->release.i_minor = 0;
    p_update->release.i_revision = 0;

    FREENULL( p_update->release.psz_url );
    FREENULL( p_update->release.psz_desc );
}

struct m_info
{
    char* os;
    char* os_ver; 
    char* os_arch;
    char* vlc_ver;
} mi;


bool fillmi()
{
    if( asprintf( &mi.vlc_ver,"%d.%d.%d.%d", PACKAGE_VERSION_MAJOR , PACKAGE_VERSION_MINOR , PACKAGE_VERSION_REVISION , PACKAGE_VERSION_EXTRA) == -1 )
    {
        return false;
    }
    
    #ifdef _WIN32
        mi.os = "Windows";
        mi.os_arch = "32";
    
    #elif _WIN64
        mi.os = "Windows";
        mi.os_arch = "64";
    
    #elif __unix__
        mi.os = "Linux";
        mi.os_arch = "Linux";    
        if( asprintf( &mi.os_ver , "Linux" ) == -1 )
        {
            return false;
        }
    #endif
    
    #ifdef _WIN32 || _WIN64
        OSVERSIONINFO osv;
        ZeroMemory( &osv, sizeof(OSVERSIONINFO) );
        osv.dwOSVersionInfoSize = sizeof( OSVERSIONINFO );
        GetVersionEx( &osv );
        int osv_x = osv.dwMajorVersion;
        int osv_y = osv.dwMinorVersion;
        int osv_z = osv.dwBuildNumber;
        int osv_o = osv.dwPlatformId;
        
        if( asprintf( &mi.os_ver, "%d.%d.%d.%d" , osv_x , osv_y , osv_z , osv_o ) == -1 )
        {
            return false;
        }
        
    #endif
    return true;
}
/**
 * Get the update file and parse it
 * p_update has to be locked when calling this function
 *
 * \param p_update pointer to update struct
 * \return true if the update is valid and authenticated
 */
static json_value * jsongetbyname( json_value *object, const char *psz_name )
{
    if ( object->type != json_object ) return NULL;
    for ( unsigned int i=0; i < object->u.object.length; i++ )
        if ( strcmp( object->u.object.values[i].name, psz_name ) == 0 )
            return object->u.object.values[i].value;
    return NULL;
}

static bool GetUpdateFile( update_t *p_update )
{

    stream_t *p_stream = NULL;
    char *psz_version_line = NULL;
    char *psz_update_data = NULL;
    char *s_url = NULL;
    
    if( fillmi() == false )
    {
        mi.vlc_ver = NULL;
        mi.os_ver = NULL;
        goto error;
    }
    
    if( asprintf( &s_url , "http://update.videolan.org/u/vlc/%s/update?os=%s&os_ver=%s&os_arch=%s&vlc_ver=%s" , BUILD_CHANNEL , mi.os , mi.os_ver , mi.os_arch , mi.vlc_ver ) == -1 )
    {
        s_url = NULL;
        goto error;
    }
    
    p_stream = vlc_stream_NewURL( p_update->p_libvlc, s_url );
    if( !p_stream )
    {
        msg_Err( p_update->p_libvlc, "Failed to open %s for reading",
                 s_url );
        goto error;
    }

    uint64_t i_read;
    if( vlc_stream_GetSize( p_stream, &i_read ) || i_read >= UINT16_MAX )
    {
        msg_Err(p_update->p_libvlc, "Status file too large");
        goto error;
    }

    psz_update_data = malloc( i_read + 1 ); /* terminating '\0' */
    if( !psz_update_data )
        goto error;

    if( vlc_stream_Read( p_stream, psz_update_data,
                         i_read ) != (ssize_t)i_read )
    {
        msg_Err( p_update->p_libvlc, "Couldn't download update file %s",
                UPDATE_VLC_STATUS_URL );
        goto error;
    }
    psz_update_data[i_read] = '\0';

    vlc_stream_Delete( p_stream );
    p_stream = NULL;

    // JSON Parsing
    // TODO : get json by name function
    json_settings settings;
    char psz_error[128];
    memset (&settings, 0, sizeof (json_settings));
    json_value *psz_update_data_parser = json_parse_ex( &settings, psz_update_data, psz_error );
    if ( psz_update_data_parser == NULL )
    {
        msg_Warn( p_update->p_libvlc, "Can't parse json data: %s", psz_error );
        goto error;
    }
    /* version number */
    size_t i_len;
    json_value *json_vlc_ver = jsongetbyname( psz_update_data_parser, "vlc_ver" );
    p_update->release.i_extra = 0;
    int ret = sscanf( json_vlc_ver->u.string.ptr, "%i.%i.%i.%i",
                    &p_update->release.i_major, &p_update->release.i_minor,
                    &p_update->release.i_revision, &p_update->release.i_extra);
    if( ret != 3 && ret != 4 )
    {
            msg_Err( p_update->p_libvlc, "Update version false formatted" );
            goto error;
    }

    /* URL */
    json_value *json_url = jsongetbyname( psz_update_data_parser, "url" );
    i_len = strlen(json_url->u.string.ptr);
    if( i_len == 0 )
    {
        msg_Err( p_update->p_libvlc, "Update file %s is corrupted: URL missing",
                 UPDATE_VLC_STATUS_URL );

        goto error;
    }

    if( !(p_update->release.psz_url = malloc( i_len + 1)) )
        goto error;
    strncpy( p_update->release.psz_url, json_url->u.string.ptr, i_len );
    p_update->release.psz_url[i_len] = '\0';

    /* Remaining data : description */
    json_value *json_desc = jsongetbyname( psz_update_data_parser, "desc" );
    i_len = strlen(json_desc->u.string.ptr);
    if( i_len == 0 )
    {
        msg_Err( p_update->p_libvlc,
                "Update file %s is corrupted: description missing",
                UPDATE_VLC_STATUS_URL );
        goto error;
    }

    if( !(p_update->release.psz_desc = malloc( i_len + 1)) )
        goto error;
    strncpy( p_update->release.psz_desc, json_desc->u.string.ptr, i_len );
    p_update->release.psz_desc[i_len] = '\0';

    /* Now that we know the status is valid, we must download its signature
     * to authenticate it */
    signature_packet_t sign;
    
    json_value *json_release_id = jsongetbyname( psz_update_data_parser, "id" );
    int release_id = json_release_id->u.integer;

    if( asprintf( &signature_url , "http://update.videolan.org/u/vlc/%s/signature?id=%d" , BUILD_CHANNEL ,release_id ) == -1 )
    {
        signature_url = NULL;
        goto error;
    }

    if( download_signature( VLC_OBJECT( p_update->p_libvlc ), &sign,
            UPDATE_VLC_STATUS_URL ) != VLC_SUCCESS )
    {
        msg_Err( p_update->p_libvlc, "Couldn't download signature of status file" );
        goto error;
    }

    if( sign.type != BINARY_SIGNATURE && sign.type != TEXT_SIGNATURE )
    {
        msg_Err( p_update->p_libvlc, "Invalid signature type" );
        goto error;
    }

    p_update->p_pkey = (public_key_t*)malloc( sizeof( public_key_t ) );
    if( !p_update->p_pkey )
        goto error;

    if( parse_public_key( videolan_public_key, sizeof( videolan_public_key ),
                        p_update->p_pkey, NULL ) != VLC_SUCCESS )
    {
        msg_Err( p_update->p_libvlc, "Couldn't parse embedded public key, something went really wrong..." );
        FREENULL( p_update->p_pkey );
        goto error;
    }

    memcpy( p_update->p_pkey->longid, videolan_public_key_longid, 8 );

    if( memcmp( sign.issuer_longid, p_update->p_pkey->longid , 8 ) != 0 )
    {
        msg_Dbg( p_update->p_libvlc, "Need to download the GPG key" );
        public_key_t *p_new_pkey = download_key(
                VLC_OBJECT(p_update->p_libvlc),
                sign.issuer_longid, videolan_public_key_longid );
        if( !p_new_pkey )
        {
            msg_Err( p_update->p_libvlc, "Couldn't download GPG key" );
            FREENULL( p_update->p_pkey );
            goto error;
        }

        uint8_t *p_hash = hash_from_public_key( p_new_pkey );
        if( !p_hash )
        {
            msg_Err( p_update->p_libvlc, "Failed to hash signature" );
            free( p_new_pkey );
            FREENULL( p_update->p_pkey );
            goto error;
        }

        if( verify_signature( &p_new_pkey->sig,
                    &p_update->p_pkey->key, p_hash ) == VLC_SUCCESS )
        {
            free( p_hash );
            msg_Info( p_update->p_libvlc, "Key authenticated" );
            free( p_update->p_pkey );
            p_update->p_pkey = p_new_pkey;
        }
        else
        {
            free( p_hash );
            msg_Err( p_update->p_libvlc, "Key signature invalid !" );
            goto error;
        }
    }

    uint8_t *p_hash = hash_from_text( psz_update_data, &sign );
    if( !p_hash )
    {
        msg_Warn( p_update->p_libvlc, "Can't compute hash for status file" );
        goto error;
    }

    else if( p_hash[0] != sign.hash_verification[0] ||
        p_hash[1] != sign.hash_verification[1] )
    {
        msg_Warn( p_update->p_libvlc, "Bad hash for status file" );
        free( p_hash );
        goto error;
    }

    else if( verify_signature( &sign, &p_update->p_pkey->key, p_hash )
            != VLC_SUCCESS )
    {
        msg_Err( p_update->p_libvlc, "BAD SIGNATURE for status file" );
        free( p_hash );
        goto error;
    }

    else
    {
        msg_Info( p_update->p_libvlc, "Status file authenticated" );
        free( p_hash );
        free( psz_update_data );
        free( s_url );
        free( mi.vlc_ver );
        free( mi.os_ver );
        return true;
    }

error:
    if( p_stream )
        vlc_stream_Delete( p_stream );
    if ( psz_update_data_parser )
        json_value_free( psz_update_data_parser );
    free( s_url );
    free( mi.vlc_ver );
    free( mi.os_ver );
    return false;
}

static void* update_CheckReal( void * );

/**
 * Check for updates
 *
 * \param p_update pointer to update struct
 * \param pf_callback pointer to a function to call when the update_check is finished
 * \param p_data pointer to some datas to give to the callback
 * \returns nothing
 */
void update_Check( update_t *p_update, void (*pf_callback)( void*, bool ), void *p_data )
{
    assert( p_update );

    // If the object already exist, destroy it
    if( p_update->p_check )
    {
        vlc_join( p_update->p_check->thread, NULL );
        free( p_update->p_check );
    }

    update_check_thread_t *p_uct = calloc( 1, sizeof( *p_uct ) );
    if( !p_uct ) return;

    p_uct->p_update = p_update;
    p_update->p_check = p_uct;
    p_uct->pf_callback = pf_callback;
    p_uct->p_data = p_data;

    vlc_clone( &p_uct->thread, update_CheckReal, p_uct, VLC_THREAD_PRIORITY_LOW );
}

void* update_CheckReal( void *obj )
{
    update_check_thread_t *p_uct = (update_check_thread_t *)obj;
    bool b_ret;
    int canc;

    canc = vlc_savecancel ();
    vlc_mutex_lock( &p_uct->p_update->lock );

    EmptyRelease( p_uct->p_update );
    b_ret = GetUpdateFile( p_uct->p_update );
    vlc_mutex_unlock( &p_uct->p_update->lock );

    if( p_uct->pf_callback )
        (p_uct->pf_callback)( p_uct->p_data, b_ret );

    vlc_restorecancel (canc);
    return NULL;
}

bool update_NeedUpgrade( update_t *p_update )
{
    assert( p_update );

    static const int current[4] = {
        PACKAGE_VERSION_MAJOR,
        PACKAGE_VERSION_MINOR,
        PACKAGE_VERSION_REVISION,
        PACKAGE_VERSION_EXTRA
    };
    const int latest[4] = {
        p_update->release.i_major,
        p_update->release.i_minor,
        p_update->release.i_revision,
        p_update->release.i_extra
    };

    for (unsigned i = 0; i < sizeof latest / sizeof *latest; i++) {
        /* there is a new version available */
        if (latest[i] > current[i])
            return true;

        /* current version is more recent than the latest version ?! */
        if (latest[i] < current[i])
            return false;
    }

    /* current version is not a release, it's a -git or -rc version */
    if (*PACKAGE_VERSION_DEV)
        return true;

    /* current version is latest version */
    return false;
}

/**
 * Convert a long int size in bytes to a string
 *
 * \param l_size the size in bytes
 * \return the size as a string
 */
static char *size_str( uint64_t l_size )
{
    char *psz_tmp = NULL;
    int i_retval = 0;
    if( l_size >> 30 )
        i_retval = asprintf( &psz_tmp, _("%.1f GiB"), (float)l_size/(1<<30) );
    else if( l_size >> 20 )
        i_retval = asprintf( &psz_tmp, _("%.1f MiB"), (float)l_size/(1<<20) );
    else if( l_size >> 10 )
        i_retval = asprintf( &psz_tmp, _("%.1f KiB"), (float)l_size/(1<<10) );
    else
        i_retval = asprintf( &psz_tmp, _("%"PRIu64" B"), l_size );

    return i_retval == -1 ? NULL : psz_tmp;
}

static void* update_DownloadReal( void * );

/**
 * Download the file given in the update_t
 *
 * \param p_update structure
 * \param dir to store the download file
 * \return nothing
 */
void update_Download( update_t *p_update, const char *psz_destdir )
{
    assert( p_update );

    // If the object already exist, destroy it
    if( p_update->p_download )
    {
        atomic_store( &p_update->p_download->aborted, true );
        vlc_join( p_update->p_download->thread, NULL );
        vlc_object_release( p_update->p_download );
    }

    update_download_thread_t *p_udt =
        vlc_custom_create( p_update->p_libvlc, sizeof( *p_udt ),
                           "update download" );
    if( !p_udt )
        return;

    p_udt->p_update = p_update;
    p_update->p_download = p_udt;
    p_udt->psz_destdir = psz_destdir ? strdup( psz_destdir ) : NULL;

    atomic_store(&p_udt->aborted, false);
    vlc_clone( &p_udt->thread, update_DownloadReal, p_udt, VLC_THREAD_PRIORITY_LOW );
}

static void* update_DownloadReal( void *obj )
{
    update_download_thread_t *p_udt = (update_download_thread_t *)obj;
    uint64_t l_size;
    uint64_t l_downloaded = 0;
    float f_progress;
    char *psz_downloaded = NULL;
    char *psz_size = NULL;
    char *psz_destfile = NULL;
    char *psz_tmpdestfile = NULL;

    FILE *p_file = NULL;
    stream_t *p_stream = NULL;
    void* p_buffer = NULL;
    int i_read;
    int canc;

    vlc_dialog_id *p_dialog_id = NULL;
    update_t *p_update = p_udt->p_update;
    char *psz_destdir = p_udt->psz_destdir;

    msg_Dbg( p_udt, "Opening Stream '%s'", p_update->release.psz_url );
    canc = vlc_savecancel ();

    /* Open the stream */
    p_stream = vlc_stream_NewURL( p_udt, p_update->release.psz_url );
    if( !p_stream )
    {
        msg_Err( p_udt, "Failed to open %s for reading", p_update->release.psz_url );
        goto end;
    }

    /* Get the stream size */
    if( vlc_stream_GetSize( p_stream, &l_size ) || l_size == 0 )
        goto end;

    /* Get the file name and open it*/
    psz_tmpdestfile = strrchr( p_update->release.psz_url, '/' );
    if( !psz_tmpdestfile )
    {
        msg_Err( p_udt, "The URL %s is badly formatted",
                 p_update->release.psz_url );
        goto end;
    }
    psz_tmpdestfile++;
    if( asprintf( &psz_destfile, "%s%s", psz_destdir, psz_tmpdestfile ) == -1 )
        goto end;

    p_file = vlc_fopen( psz_destfile, "w" );
    if( !p_file )
    {
        msg_Err( p_udt, "Failed to open %s for writing", psz_destfile );
        dialog_FatalWait( p_udt, _("Saving file failed"),
            _("Failed to open \"%s\" for writing"),
             psz_destfile );
        goto end;
    }

    /* Create a buffer and fill it with the downloaded file */
    p_buffer = (void *)malloc( 1 << 10 );
    if( unlikely(p_buffer == NULL) )
        goto end;

    msg_Dbg( p_udt, "Downloading Stream '%s'", p_update->release.psz_url );

    psz_size = size_str( l_size );

    p_dialog_id =
        vlc_dialog_display_progress( p_udt, false, 0.0, _("Cancel"),
                                     ( "Downloading..."),
                                     _("%s\nDownloading... %s/%s %.1f%% done"),
                                     p_update->release.psz_url, "0.0", psz_size,
                                     0.0 );

    if( p_dialog_id == NULL )
        goto end;

    while( !atomic_load( &p_udt->aborted ) &&
           ( i_read = vlc_stream_Read( p_stream, p_buffer, 1 << 10 ) ) &&
           !vlc_dialog_is_cancelled( p_udt, p_dialog_id ) )
    {
        if( fwrite( p_buffer, i_read, 1, p_file ) < 1 )
        {
            msg_Err( p_udt, "Failed to write into %s", psz_destfile );
            break;
        }

        l_downloaded += i_read;
        psz_downloaded = size_str( l_downloaded );
        f_progress = (float)l_downloaded/(float)l_size;

        vlc_dialog_update_progress_text( p_udt, p_dialog_id, f_progress,
                                         "%s\nDownloading... %s/%s - %.1f%% done",
                                         p_update->release.psz_url,
                                         psz_downloaded, psz_size,
                                         f_progress*100 );
        free( psz_downloaded );
    }

    /* Finish the progress bar or delete the file if the user had canceled */
    fclose( p_file );
    p_file = NULL;

    if( !atomic_load( &p_udt->aborted ) &&
        !vlc_dialog_is_cancelled( p_udt, p_dialog_id ) )
    {
        vlc_dialog_release( p_udt, p_dialog_id );
        p_dialog_id = NULL;
    }
    else
    {
        vlc_unlink( psz_destfile );
        goto end;
    }

    signature_packet_t sign;
    if( download_signature( VLC_OBJECT( p_udt ), &sign,
            p_update->release.psz_url ) != VLC_SUCCESS )
    {
        vlc_unlink( psz_destfile );

        dialog_FatalWait( p_udt, _("File could not be verified"),
            _("It was not possible to download a cryptographic signature for "
              "the downloaded file \"%s\". Thus, it was deleted."),
            psz_destfile );
        msg_Err( p_udt, "Couldn't download signature of downloaded file" );
        goto end;
    }

    if( memcmp( sign.issuer_longid, p_update->p_pkey->longid, 8 ) )
    {
        vlc_unlink( psz_destfile );
        msg_Err( p_udt, "Invalid signature issuer" );
        dialog_FatalWait( p_udt, _("Invalid signature"),
            _("The cryptographic signature for the downloaded file \"%s\" was "
              "invalid and could not be used to securely verify it. Thus, the "
              "file was deleted."),
            psz_destfile );
        goto end;
    }

    if( sign.type != BINARY_SIGNATURE )
    {
        vlc_unlink( psz_destfile );
        msg_Err( p_udt, "Invalid signature type" );
        dialog_FatalWait( p_udt, _("Invalid signature"),
            _("The cryptographic signature for the downloaded file \"%s\" was "
              "invalid and could not be used to securely verify it. Thus, the "
              "file was deleted."),
            psz_destfile );
        goto end;
    }

    uint8_t *p_hash = hash_from_file( psz_destfile, &sign );
    if( !p_hash )
    {
        msg_Err( p_udt, "Unable to hash %s", psz_destfile );
        vlc_unlink( psz_destfile );
        dialog_FatalWait( p_udt, _("File not verifiable"),
            _("It was not possible to securely verify the downloaded file"
              " \"%s\". Thus, it was deleted."),
            psz_destfile );

        goto end;
    }

    if( p_hash[0] != sign.hash_verification[0] ||
        p_hash[1] != sign.hash_verification[1] )
    {
        vlc_unlink( psz_destfile );
        dialog_FatalWait( p_udt, _("File corrupted"),
            _("Downloaded file \"%s\" was corrupted. Thus, it was deleted."),
             psz_destfile );
        msg_Err( p_udt, "Bad hash for %s", psz_destfile );
        free( p_hash );
        goto end;
    }

    if( verify_signature( &sign, &p_update->p_pkey->key, p_hash )
            != VLC_SUCCESS )
    {
        vlc_unlink( psz_destfile );
        dialog_FatalWait( p_udt, _("File corrupted"),
            _("Downloaded file \"%s\" was corrupted. Thus, it was deleted."),
             psz_destfile );
        msg_Err( p_udt, "BAD SIGNATURE for %s", psz_destfile );
        free( p_hash );
        goto end;
    }

    msg_Info( p_udt, "%s authenticated", psz_destfile );
    free( p_hash );

#ifdef _WIN32
    const char *psz_msg =
        _("The new version was successfully downloaded."
        "Do you want to close VLC and install it now?");
    int answer = vlc_dialog_wait_question( p_udt, VLC_DIALOG_QUESTION_NORMAL,
                                           _("Cancel"), _("Install"), NULL,
                                           _("Update VLC media player"), "%s",
                                           psz_msg );
    if(answer == 1)
    {
        wchar_t psz_wdestfile[MAX_PATH];
        MultiByteToWideChar( CP_UTF8, 0, psz_destfile, -1, psz_wdestfile, MAX_PATH );
        answer = (int)ShellExecuteW( NULL, L"open", psz_wdestfile, NULL, NULL, SW_SHOW);
        if(answer > 32)
            libvlc_Quit(p_udt->obj.libvlc);
    }
#endif
end:
    if( p_dialog_id != NULL )
        vlc_dialog_release( p_udt, p_dialog_id );
    if( p_stream )
        vlc_stream_Delete( p_stream );
    if( p_file )
        fclose( p_file );
    free( psz_destdir );
    free( psz_destfile );
    free( p_buffer );
    free( psz_size );

    vlc_restorecancel( canc );
    return NULL;
}

update_release_t *update_GetRelease( update_t *p_update )
{
    return &p_update->release;
}
