/*! \file   janus_native_client.c
 * \author Chetan NAIK <chetan@packetservo.com>
 * \copyright GNU General Public License v3
 * \brief  Janus NativeClient plugin
 * \details  This is a simple native client plugin for Janus, allowing two
 * WebRTC peers to call each other through the gateway. The idea is to
 * provide a similar service as the well known AppRTC demo (https://apprtc.appspot.com),
 * but with the media flowing through the gateway rather than being peer-to-peer.
 * 
 * The plugin provides a simple fake registration mechanism. A peer attaching
 * to the plugin needs to specify a username, which acts as a "phone number":
 * if the username is free, it is associated with the peer, which means
 * he/she can be "called" using that username by another peer. Peers can
 * either "call" another peer, by specifying their username, or wait for a call.
 * The approach used by this plugin is similar to the one employed by the
 * echo test one: all frames (RTP/RTCP) coming from one peer are relayed
 * to the other.
 * 
 * Just as in the janus_nativeclient.c plugin, there are knobs to control
 * whether audio and/or video should be muted or not, and if the bitrate
 * of the peer needs to be capped by means of REMB messages.
 * 
 * \section vcallapi Video Call API
 * 
 * All requests you can send in the Video Call API are asynchronous,
 * which means all responses (successes and errors) will be delivered
 * as events with the same transaction. 
 * 
 * The supported requests are \c list , \c register , \c call ,
 * \c accept , \c set and \c hangup . \c list allows you to get a list
 * of all the registered peers; \c register can be used to register
 * a username to call and be called; \c call is used to start a video
 * call with somebody through the plugin, while \c accept is used to
 * accept the call in case one is invited instead of inviting; \c set
 * can be used to configure some call-related settings (e.g., a cap on
 * the send bandwidth); finally, \c hangup can be used to terminate the
 * communication at any time, either to hangup an ongoing call or to
 * cancel/decline a call that hasn't started yet.
 * 
 * The \c list request has to be formatted as follows:
 * 
\verbatim
{
	"request" : "list"
}
\endverbatim
 *
 * A successful request will result in an array of peers to be returned:
 * 
\verbatim
{
	"videocall" : "event",
	"result" : {
		"list": [	// Array of peers
			"alice78",
			"bob51",
			// others
		]
	}
}
\endverbatim
 * 
 * An error instead (and the same applies to all other requests, so this
 * won't be repeated) would provide both an error code and a more verbose
 * description of the cause of the issue:
 * 
\verbatim
{
	"videocall" : "event",
	"error_code" : <numeric ID, check Macros below>,
	"error" : "<error description as a string>"
}
\endverbatim
 * 
 * To register a username to call and be called, the \c register request
 * can be used. This works on a "first come, first served" basis: there's
 * no authetication involved, you just specify the username you'd like
 * to use and, if free, it's assigned to you. The \c request has to be
 * formatted as follows:
 * 
\verbatim
{
	"request" : "register",
	"username" : "<desired unique username>"
}
\endverbatim
 * 
 * If successul, this will result in a \c registered event:
 * 
\verbatim
{
	"videocall" : "event",
	"result" : {
		"event" : "registered",
		"username" : "<same username, registered>"
	}
}
\endverbatim
 * 
 * Once you're registered, you can either start a new call or wait to
 * be called by someone else who knows your username. To start a new
 * call, the \c call request can be used: this request must be attached
 * to a JSEP offer containing the WebRTC-related info to setup a new
 * media session. A \c call request has to be formatted as follows:
 * 
\verbatim
{
	"request" : "call",
	"username" : "<username to call>"
}
\endverbatim
 * 
 * If successul, this will result in a \c calling event:
 * 
\verbatim
{
	"videocall" : "event",
	"result" : {
		"event" : "calling",
		"username" : "<same username, registered>"
	}
}
\endverbatim
 *
 * At the same time, the user being called will receive an
 * \c incomingcall event
 *  
\verbatim
{
	"videocall" : "event",
	"result" : {
		"event" : "incomingcall",
		"username" : "<your username>"
	}
}
\endverbatim
 * 
 * To accept the call, the \c accept request can be used. This request
 * must be attached to a JSEP answer containing the WebRTC-related
 * information to complete the actual PeerConnection setup. A \c accept
 * request has to be formatted as follows:
 * 
\verbatim
{
	"request" : "accept"
}
\endverbatim
 * 
 * If successul, both the caller and the callee will receive an
 * \c accepted event to notify them about the success of the signalling:
 * 
\verbatim
{
	"videocall" : "event",
	"result" : {
		"event" : "accepted",
		"username" : "<caller username>"
	}
}
\endverbatim
 *
 * At this point, the media-related settings of the call can be modified
 * on either side by means of a \c set request, which acts pretty much
 * as the one in the \ref echoapi . The \c set request has to be
 * formatted as follows. All the attributes (except \c request) are
 * optional, so any request can contain a subset of them:
 *
\verbatim
{
	"request" : "set",
	"audio" : true|false,
	"video" : true|false,
	"bitrate" : <numeric bitrate value>,
	"record" : true|false,
	"filename" : <base path/filename to use for the recording>
}
\endverbatim
 *
 * \c audio instructs the plugin to do or do not relay audio frames;
 * \c video does the same for video; \c bitrate caps the bandwidth to
 * force on the browser encoding side (e.g., 128000 for 128kbps);
 * \c record enables or disables the recording of this peer; in case
 * recording is enabled, \c filename allows to specify a base
 * path/filename to use for the files (-audio.mjr and -video.mjr are
 * automatically appended). Beware that enabling the recording only
 * records this user's contribution, and not the whole call: to record
 * both sides, you need to enable recording for both the peers in the
 * call.
 * 
 * A successful request will result in a \c set event:
 * 
\verbatim
{
	"videocall" : "event",
	"result" : {
		"event" : "set"
	}
}
\endverbatim
 * 
 * To decline an incoming call, cancel an attempt to call or simply
 * hangup an ongoing conversation, the \c hangup request can be used,
 * which has to be formatted as follows:
 * 
\verbatim
{
	"request" : "hangup"
}
\endverbatim
 *
 * Whatever the reason of a call being closed (e.g., a \c hangup request,
 * a PeerConnection being closed, or something else), both parties in
 * the communication will receive a \c hangup event:
 * 
\verbatim
{
	"videocall" : "event",
	"result" : {
		"event" : "hangup",
		"username" : "<username of who closed the communication>",
		"reason" : "<description of what happened>"
	}
}
\endverbatim
 * 
 * \ingroup plugins
 * \ref plugins
 */

#include "plugin.h"

#include <jansson.h>
#include <gst/gst.h>
#include <gst/app/gstappsink.h>
#include <gst/app/gstappsrc.h>

#include "../debug.h"
#include "../apierror.h"
#include "../config.h"
#include "../mutex.h"
#include "../record.h"
#include "../rtp.h"
#include "../rtcp.h"
#include "../utils.h"


/* Plugin information */
#define JANUS_NATIVECLIENT_VERSION			1
#define JANUS_NATIVECLIENT_VERSION_STRING	"0.0.1"
#define JANUS_NATIVECLIENT_DESCRIPTION		"JANUS Native client plugin"
#define JANUS_NATIVECLIENT_NAME			"JANUS Native client plugin"
#define JANUS_NATIVECLIENT_AUTHOR			"PacketServo"
#define JANUS_NATIVECLIENT_PACKAGE			"janus.plugin.nativeclient"

/* Plugin methods */
janus_plugin *create(void);
int janus_nativeclient_init(janus_callbacks *callback, const char *config_path);
void janus_nativeclient_destroy(void);
int janus_nativeclient_get_api_compatibility(void);
int janus_nativeclient_get_version(void);
const char *janus_nativeclient_get_version_string(void);
const char *janus_nativeclient_get_description(void);
const char *janus_nativeclient_get_name(void);
const char *janus_nativeclient_get_author(void);
const char *janus_nativeclient_get_package(void);
void janus_nativeclient_create_session(janus_plugin_session *handle, int *error);
struct janus_plugin_result *janus_nativeclient_handle_message(janus_plugin_session *handle, char *transaction, json_t *message, json_t *jsep);
void janus_nativeclient_setup_media(janus_plugin_session *handle);
void janus_nativeclient_incoming_rtp(janus_plugin_session *handle, int video, char *buf, int len);
void janus_nativeclient_incoming_rtcp(janus_plugin_session *handle, int video, char *buf, int len);
void janus_nativeclient_incoming_data(janus_plugin_session *handle, char *buf, int len);
void janus_nativeclient_slow_link(janus_plugin_session *handle, int uplink, int video);
void janus_nativeclient_hangup_media(janus_plugin_session *handle);
void janus_nativeclient_destroy_session(janus_plugin_session *handle, int *error);
json_t *janus_nativeclient_query_session(janus_plugin_session *handle);

/* Plugin setup */
static janus_plugin janus_nativeclient_plugin =
	JANUS_PLUGIN_INIT (
		.init = janus_nativeclient_init,
		.destroy = janus_nativeclient_destroy,

		.get_api_compatibility = janus_nativeclient_get_api_compatibility,
		.get_version = janus_nativeclient_get_version,
		.get_version_string = janus_nativeclient_get_version_string,
		.get_description = janus_nativeclient_get_description,
		.get_name = janus_nativeclient_get_name,
		.get_author = janus_nativeclient_get_author,
		.get_package = janus_nativeclient_get_package,
		
		.create_session = janus_nativeclient_create_session,
		.handle_message = janus_nativeclient_handle_message,
		.setup_media = janus_nativeclient_setup_media,
		.incoming_rtp = janus_nativeclient_incoming_rtp,
		.incoming_rtcp = janus_nativeclient_incoming_rtcp,
		.incoming_data = janus_nativeclient_incoming_data,
		.slow_link = janus_nativeclient_slow_link,
		.hangup_media = janus_nativeclient_hangup_media,
		.destroy_session = janus_nativeclient_destroy_session,
		.query_session = janus_nativeclient_query_session,
	);

/* Plugin creator */
janus_plugin *create(void) {
	JANUS_LOG(LOG_VERB, "%s created!\n", JANUS_NATIVECLIENT_NAME);
	return &janus_nativeclient_plugin;
}

/* Parameter validation */
static struct janus_json_parameter event_parameters[] = {
	{"event", JSON_STRING, JANUS_JSON_PARAM_REQUIRED}
};
/*
static struct janus_json_parameter username_parameters[] = {
	{"username", JSON_STRING, JANUS_JSON_PARAM_REQUIRED}
};
static struct janus_json_parameter set_parameters[] = {
	{"audio", JANUS_JSON_BOOL, 0},
	{"video", JANUS_JSON_BOOL, 0},
	{"bitrate", JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	{"record", JANUS_JSON_BOOL, 0},
	{"filename", JSON_STRING, 0}
};*/

/* Useful stuff */
static volatile gint initialized = 0, stopping = 0;
static janus_callbacks *gateway = NULL;
static GThread *handler_thread;
static GThread *watchdog;
static void *janus_nativeclient_handler(void *data);
static void *janus_nativeclient_relay_thread (void * data);
static void *janus_nativeclient_aplayer_thread (void * data);

typedef struct janus_nativeclient_rtp_source {
	GstElement * vsource, * vfilter, * vparser, * parserfilter, * vrtppay, * vsink; 
	GstElement * asource, * afilter, * aencoder, * artppay, * asink; 
	GstElement * resample;
	GstElement * pipeline;
	GstBus * bus;
	GstCaps * afiltercaps, * vfiltercaps, * parsercaps;
	gint64 last_received_video;
	gint64 last_received_audio;
} janus_nativeclient_rtp_source;

typedef struct janus_nativeclient_audio_player {
	GstElement * asource, * afilter, * artpdepay;
	GstElement * adecoder, * aconvert, * aoutput;
	GstElement * aresample;
	GstElement * apipeline;
	GstCaps * afiltercaps;
	gboolean isaCapsSet;
	GstBus * abus;
	gint64 last_received_audio;
} janus_nativeclient_audio_player;

typedef struct janus_audio_packet {
	char * data;
	gint length;
	gint is_video;
} janus_audio_packet;
static janus_audio_packet eos_apacket;

typedef struct janus_nativeclient_message {
	janus_plugin_session *handle;
	char *transaction;
	json_t *message;
	json_t *jsep;
} janus_nativeclient_message;
static GAsyncQueue *messages = NULL;
static janus_nativeclient_message exit_message;

static void janus_nativeclient_message_free(janus_nativeclient_message *msg) {
	if(!msg || msg == &exit_message)
		return;

	msg->handle = NULL;

	g_free(msg->transaction);
	msg->transaction = NULL;
	if(msg->message)
		json_decref(msg->message);
	msg->message = NULL;
	if(msg->jsep)
		json_decref(msg->jsep);
	msg->jsep = NULL;

	g_free(msg);
}

typedef struct janus_nativeclient_session {
	janus_plugin_session *handle;
	gchar *username;
	gboolean started;
	gboolean play_audio;
	gboolean send_audio;
	gboolean send_video;
	janus_nativeclient_audio_player * aplayer;
	janus_nativeclient_rtp_source * rtp_source;
	GAsyncQueue * apackets;
	gboolean stopping;
	uint64_t bitrate;
	guint16 slowlink_count;
	volatile gint hangingup;
	gint64 destroyed;	/* Time at which this session was marked as destroyed */
} janus_nativeclient_session;
static GHashTable *sessions;
static GList *old_sessions;
static janus_mutex sessions_mutex;

/* SDP offer/answer templates for the playout */
#define OPUS_PT		111
#define VP8_PT		100
#define sdp_template \
		"v=0\r\n" \
		"o=- %"SCNu64" %"SCNu64" IN IP4 127.0.0.1\r\n"	/* We need current time here */ \
		"s=%s\r\n"							/* Recording playout id */ \
		"t=0 0\r\n" \
		"%s%s%s"								/* Audio and/or video m-lines */
#define sdp_a_template \
		"m=audio 1 RTP/SAVPF %d\r\n"		/* Opus payload type */ \
		"c=IN IP4 1.1.1.1\r\n" \
		"a=%s\r\n"							/* Media direction */ \
		"a=rtpmap:%d opus/48000/2\r\n"		/* Opus payload type */
#define sdp_v_template \
		"m=video 1 RTP/SAVPF %d\r\n"		/* VP8 payload type */ \
		"c=IN IP4 1.1.1.1\r\n" \
		"a=%s\r\n"							/* Media direction */ \
		"a=rtpmap:%d H264/90000\r\n"		/* VP8 payload type */ \
		"a=fmtp:%d %s\r\n"                  /*profile-level-id=42e01f;packetization-mode=1"*/\
		"a=rtcp-fb:%d ccm fir\r\n"			/* VP8 payload type */ \
		"a=rtcp-fb:%d nack\r\n"				/* VP8 payload type */ \
		"a=rtcp-fb:%d nack pli\r\n"			/* VP8 payload type */ \
		"a=rtcp-fb:%d goog-remb\r\n"		/* VP8 payload type */
#define sdp_d_template \
		"m=application 1 DTLS/SCTP 5000\r\n" \
		"c=IN IP4 1.1.1.1\r\n" \
		"a=sctpmap:5000 webrtc-datachannel 16\r\n"
		
/* Error codes */
#define JANUS_NATIVECLIENT_ERROR_UNKNOWN_ERROR			499
#define JANUS_NATIVECLIENT_ERROR_NO_MESSAGE			470
#define JANUS_NATIVECLIENT_ERROR_INVALID_JSON			471
#define JANUS_NATIVECLIENT_ERROR_INVALID_REQUEST		472
#define JANUS_NATIVECLIENT_ERROR_REGISTER_FIRST		473
#define JANUS_NATIVECLIENT_ERROR_INVALID_ELEMENT		474
#define JANUS_NATIVECLIENT_ERROR_MISSING_ELEMENT		475
#define JANUS_NATIVECLIENT_ERROR_USERNAME_TAKEN		476
#define JANUS_NATIVECLIENT_ERROR_ALREADY_REGISTERED	477
#define JANUS_NATIVECLIENT_ERROR_NO_SUCH_USERNAME		478
#define JANUS_NATIVECLIENT_ERROR_USE_ECHO_TEST			479
#define JANUS_NATIVECLIENT_ERROR_ALREADY_IN_CALL		480
#define JANUS_NATIVECLIENT_ERROR_NO_CALL				481
#define JANUS_NATIVECLIENT_ERROR_MISSING_SDP			482


/* NativeClient watchdog/garbage collector (sort of) */
void *janus_nativeclient_watchdog(void *data);
void *janus_nativeclient_watchdog(void *data) {
	JANUS_LOG(LOG_INFO, "NativeClient watchdog started\n");
	gint64 now = 0;
	while(g_atomic_int_get(&initialized) && !g_atomic_int_get(&stopping)) {
		janus_mutex_lock(&sessions_mutex);
		/* Iterate on all the sessions */
		now = janus_get_monotonic_time();
		if(old_sessions != NULL) {
			GList *sl = old_sessions;
			JANUS_LOG(LOG_HUGE, "Checking %d old NativeClient sessions...\n", g_list_length(old_sessions));
			while(sl) {
				janus_nativeclient_session *session = (janus_nativeclient_session *)sl->data;
				if(!session) {
					sl = sl->next;
					continue;
				}
				if(now-session->destroyed >= 5*G_USEC_PER_SEC) {
					/* We're lazy and actually get rid of the stuff only after a few seconds */
					JANUS_LOG(LOG_VERB, "Freeing old NativeClient session\n");
					GList *rm = sl->next;
					old_sessions = g_list_delete_link(old_sessions, sl);
					sl = rm;
					session->handle = NULL;
					g_free(session);
					session = NULL;
					continue;
				}
				sl = sl->next;
			}
		}
		janus_mutex_unlock(&sessions_mutex);
		g_usleep(500000);
	}
	JANUS_LOG(LOG_INFO, "NativeClient watchdog stopped\n");
	return NULL;
}


/* Plugin implementation */
int janus_nativeclient_init(janus_callbacks *callback, const char *config_path) {
	if(g_atomic_int_get(&stopping)) {
		/* Still stopping from before */
		return -1;
	}
	if(callback == NULL || config_path == NULL) {
		/* Invalid arguments */
		return -1;
	}

	/* Read configuration */
	char filename[255];
	g_snprintf(filename, 255, "%s/%s.cfg", config_path, JANUS_NATIVECLIENT_PACKAGE);
	JANUS_LOG(LOG_VERB, "Configuration file: %s\n", filename);
	janus_config *config = janus_config_parse(filename);
	if(config != NULL)
		janus_config_print(config);
	/* This plugin actually has nothing to configure... */
	janus_config_destroy(config);
	config = NULL;
	
	/* Initialize GStreamer */
	gst_init (NULL, NULL);
	
	sessions = g_hash_table_new(g_str_hash, g_str_equal);
	janus_mutex_init(&sessions_mutex);
	messages = g_async_queue_new_full((GDestroyNotify) janus_nativeclient_message_free);
	/* This is the callback we'll need to invoke to contact the gateway */
	gateway = callback;

	g_atomic_int_set(&initialized, 1);

	GError *error = NULL;
	/* Start the sessions watchdog */
	watchdog = g_thread_try_new("nativeclient watchdog", &janus_nativeclient_watchdog, NULL, &error);
	if(error != NULL) {
		g_atomic_int_set(&initialized, 0);
		JANUS_LOG(LOG_ERR, "Got error %d (%s) trying to launch the NativeClient watchdog thread...\n", error->code, error->message ? error->message : "??");
		return -1;
	}
	/* Launch the thread that will handle incoming messages */
	handler_thread = g_thread_try_new("nativeclient handler", janus_nativeclient_handler, NULL, &error);
	if(error != NULL) {
		g_atomic_int_set(&initialized, 0);
		JANUS_LOG(LOG_ERR, "Got error %d (%s) trying to launch the NativeClient handler thread...\n", error->code, error->message ? error->message : "??");
		return -1;
	}
	JANUS_LOG(LOG_INFO, "%s initialized!\n", JANUS_NATIVECLIENT_NAME);
	return 0;
}

void janus_nativeclient_destroy(void) {
	if(!g_atomic_int_get(&initialized))
		return;
	g_atomic_int_set(&stopping, 1);

	g_async_queue_push(messages, &exit_message);
	if(handler_thread != NULL) {
		g_thread_join(handler_thread);
		handler_thread = NULL;
	}
	if(watchdog != NULL) {
		g_thread_join(watchdog);
		watchdog = NULL;
	}
	
	/* FIXME We should destroy the sessions cleanly */
	janus_mutex_lock(&sessions_mutex);
	GHashTableIter iter;
	gpointer value;
	g_hash_table_iter_init (&iter, sessions);
	while (g_hash_table_iter_next (&iter, NULL, &value)) {
		janus_nativeclient_session * session = value;
		if (!session->destroyed && session->aplayer != NULL) {
			janus_nativeclient_audio_player * player = session->aplayer;
			gst_object_unref (player->abus);
			gst_element_set_state (player->apipeline, GST_STATE_NULL);
			if (gst_element_get_state (player->apipeline, NULL, NULL, GST_CLOCK_TIME_NONE) == GST_STATE_CHANGE_FAILURE) {
				JANUS_LOG (LOG_ERR, "Unable to stop GSTREAMER audio player..!!\n");
			}
			gst_object_unref (GST_OBJECT(player->apipeline));
		}
		if (!session->destroyed && session->rtp_source != NULL) {
			janus_nativeclient_rtp_source * rtp_source = session->rtp_source;
			gst_object_unref (rtp_source->bus);
			gst_element_set_state (rtp_source->pipeline, GST_STATE_NULL);
			if (gst_element_get_state (rtp_source->pipeline, NULL, NULL, GST_CLOCK_TIME_NONE) == GST_STATE_CHANGE_FAILURE) {
				JANUS_LOG (LOG_ERR, "Unable to stop GSTREAMER rtp source..!!\n");
			}
			gst_object_unref (GST_OBJECT(rtp_source->pipeline));
		}
		session->destroyed = janus_get_monotonic_time();
		g_hash_table_remove(sessions, session->handle);
		old_sessions = g_list_append(old_sessions, session);
	}
	g_hash_table_destroy(sessions);
	janus_mutex_unlock(&sessions_mutex);
	g_async_queue_unref(messages);
	messages = NULL;
	sessions = NULL;
	g_atomic_int_set(&initialized, 0);
	g_atomic_int_set(&stopping, 0);
	JANUS_LOG(LOG_INFO, "%s destroyed!\n", JANUS_NATIVECLIENT_NAME);
}

int janus_nativeclient_get_api_compatibility(void) {
	/* Important! This is what your plugin MUST always return: don't lie here or bad things will happen */
	return JANUS_PLUGIN_API_VERSION;
}

int janus_nativeclient_get_version(void) {
	return JANUS_NATIVECLIENT_VERSION;
}

const char *janus_nativeclient_get_version_string(void) {
	return JANUS_NATIVECLIENT_VERSION_STRING;
}

const char *janus_nativeclient_get_description(void) {
	return JANUS_NATIVECLIENT_DESCRIPTION;
}

const char *janus_nativeclient_get_name(void) {
	return JANUS_NATIVECLIENT_NAME;
}

const char *janus_nativeclient_get_author(void) {
	return JANUS_NATIVECLIENT_AUTHOR;
}

const char *janus_nativeclient_get_package(void) {
	return JANUS_NATIVECLIENT_PACKAGE;
}

void janus_nativeclient_create_session(janus_plugin_session *handle, int *error) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized)) {
		*error = -1;
		return;
	}
	janus_nativeclient_session *session = (janus_nativeclient_session *)g_malloc0(sizeof(janus_nativeclient_session));
	if(session == NULL) {
		JANUS_LOG(LOG_FATAL, "Memory error!\n");
		*error = -2;
		return;
	}
	
	session->handle = handle;
	session->started = FALSE;
	session->play_audio = FALSE;
	session->send_audio = TRUE;
	session->send_video = TRUE;
	session->bitrate = 0;	/* No limit */
	session->username = NULL;
	session->destroyed = 0;
	g_atomic_int_set(&session->hangingup, 0);
	handle->plugin_handle = session;
	janus_mutex_lock(&sessions_mutex);
	g_hash_table_insert(sessions, handle, session);
	janus_mutex_unlock(&sessions_mutex);

	return;
}

void janus_nativeclient_destroy_session(janus_plugin_session *handle, int *error) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized)) {
		*error = -1;
		return;
	}
	janus_nativeclient_session *session = (janus_nativeclient_session *)handle->plugin_handle; 
	if(!session) {
		JANUS_LOG(LOG_ERR, "No NativeClient session associated with this handle...\n");
		*error = -2;
		return;
	}
	janus_mutex_lock(&sessions_mutex);
	if(!session->destroyed) {
		if (session->apackets != NULL)
			g_async_queue_push(session->apackets, &eos_apacket);

		session->destroyed = janus_get_monotonic_time();
		g_hash_table_remove(sessions, handle);
		
		old_sessions = g_list_append(old_sessions, session);
	}
	janus_mutex_unlock(&sessions_mutex);
	JANUS_LOG (LOG_VERB, "NativeClient session removed...\n");
	return;
}

json_t *janus_nativeclient_query_session(janus_plugin_session *handle) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized)) {
		return NULL;
	}	
	janus_nativeclient_session *session = (janus_nativeclient_session *)handle->plugin_handle;
	if(!session) {
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		return NULL;
	}
	/* Provide some generic info, e.g., if we're in a call and with whom */
	json_t *info = json_object();
	return info;
}

struct janus_plugin_result *janus_nativeclient_handle_message(janus_plugin_session *handle, char *transaction, json_t *message, json_t *jsep) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return janus_plugin_result_new(JANUS_PLUGIN_ERROR, g_atomic_int_get(&stopping) ? "Shutting down" : "Plugin not initialized", NULL);
	janus_nativeclient_message *msg = g_malloc0(sizeof(janus_nativeclient_message));
	msg->handle = handle;
	msg->transaction = transaction;
	msg->message = message;
	msg->jsep = jsep;
	g_async_queue_push(messages, msg);

	/* All the requests to this plugin are handled asynchronously */
	return janus_plugin_result_new(JANUS_PLUGIN_OK_WAIT, NULL, NULL);
}

void janus_nativeclient_setup_media(janus_plugin_session *handle) {
	JANUS_LOG(LOG_INFO, "WebRTC media is now available\n");
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return;
	janus_nativeclient_session *session = (janus_nativeclient_session *)handle->plugin_handle;	
	if(!session) {
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		return;
	}
	if(session->destroyed)
		return;
	g_atomic_int_set(&session->hangingup, 0);
	
	janus_nativeclient_rtp_source * rtp_source = (janus_nativeclient_rtp_source *)g_malloc0 (sizeof(janus_nativeclient_rtp_source));
	
	if (session->send_video) {
		rtp_source->vsource = gst_element_factory_make("rpicamsrc", "vsource");
		rtp_source->vfilter = gst_element_factory_make("capsfilter", "vfilter");
		rtp_source->vparser = gst_element_factory_make ("h264parse", "vparser");
		rtp_source->parserfilter = gst_element_factory_make ("capsfilter", "parserfilter");
		rtp_source->vrtppay = gst_element_factory_make("rtph264pay", "vrtppay");
		rtp_source->vsink = gst_element_factory_make("appsink","vsink");
		
		rtp_source->parsercaps = gst_caps_new_simple ("video/x-h264",
									"alignment", G_TYPE_STRING, "au",
									"stream-format", G_TYPE_STRING, "avc",
									NULL);
		rtp_source->vfiltercaps = gst_caps_new_simple ("video/x-h264",
									"width", G_TYPE_INT, 320,
									"height", G_TYPE_INT, 240,
									"framerate", GST_TYPE_FRACTION, 15, 1,
									"profile", G_TYPE_STRING, "baseline",
									NULL);
		
		g_object_set (rtp_source->vfilter, "caps", rtp_source->vfiltercaps, NULL);
		g_object_set (rtp_source->parserfilter, "caps", rtp_source->parsercaps, NULL);
		g_object_set (rtp_source->vsource, "bitrate", 1024 * 2048 * 8, NULL);
		g_object_set (rtp_source->vsource, "exposure-mode", 10, NULL);
		g_object_set (rtp_source->vsource, "preview", FALSE, NULL);
		g_object_set (rtp_source->vsource, "rotation", 180, NULL);
		//g_object_set (rtp_source->vsource, "inline-headers", TRUE, NULL);
		g_object_set (rtp_source->vrtppay, "pt", 97, NULL);
		g_object_set (rtp_source->vrtppay, "config-interval", 1, NULL);
		g_object_set (rtp_source->vsource, "annotation-mode", 0x1 + 0x4 + 0x8, NULL);
		g_object_set (rtp_source->vsource, "annotation-text", "PacketServo ", NULL);
		g_object_set (rtp_source->vsource, "annotation-text-size", 15, NULL);
		g_object_set (rtp_source->vsink, "max-buffers", 50, NULL);
		g_object_set (rtp_source->vsink, "drop", TRUE, NULL);
		
		gst_caps_unref (rtp_source->vfiltercaps);
		gst_caps_unref (rtp_source->parsercaps);
	}
	if (session->send_audio) {
		rtp_source->asource = gst_element_factory_make("alsasrc", "asource");
		rtp_source->resample = gst_element_factory_make("audioresample", "resample");
		rtp_source->afilter = gst_element_factory_make("capsfilter", "afilter");
		rtp_source->aencoder = gst_element_factory_make("opusenc", "aencoder");
		rtp_source->artppay = gst_element_factory_make("rtpopuspay", "artppay");
		rtp_source->asink = gst_element_factory_make("appsink", "asink");
		
		rtp_source->afiltercaps = gst_caps_new_simple ("audio/x-raw",
									"channels", G_TYPE_INT, 1,
									"rate", G_TYPE_INT, 16000,
									NULL);
		g_object_set (rtp_source->asource, "device", "hw:1", NULL);
		g_object_set (rtp_source->afilter, "caps", rtp_source->afiltercaps, NULL);
		g_object_set (rtp_source->asink, "max-buffers", 50, NULL);
		g_object_set (rtp_source->asink, "drop", TRUE, NULL);
		
		gst_caps_unref (rtp_source->afiltercaps);
	}
	
	if (rtp_source != NULL && (session->send_video || session->send_audio)) {
		rtp_source->pipeline = gst_pipeline_new ("pipeline");
		if (session->send_video && session->send_audio) {
			gst_bin_add_many (GST_BIN (rtp_source->pipeline), rtp_source->asource,
				rtp_source->resample, rtp_source->afilter, rtp_source->aencoder, rtp_source->artppay,
				rtp_source->asink, rtp_source->vsource, rtp_source->vfilter,
				rtp_source->vparser, rtp_source->parserfilter, rtp_source->vrtppay, rtp_source->vsink, NULL);
			
			if ((gst_element_link_many (rtp_source->asource, rtp_source->resample, rtp_source->afilter, rtp_source->aencoder, rtp_source->artppay, rtp_source->asink, NULL) != TRUE ) 
				|| (gst_element_link_many (rtp_source->vsource, rtp_source->vfilter, rtp_source->vparser, rtp_source->parserfilter, rtp_source->vrtppay, rtp_source->vsink, NULL) != TRUE)) {
				JANUS_LOG (LOG_ERR, "Failed to link GStreamer audio video elements\n");
				gst_object_unref (GST_OBJECT (rtp_source->pipeline));
				g_free(rtp_source);
				return;
			}
		} else if (session->send_video && !session->send_audio) {
			gst_bin_add_many (GST_BIN (rtp_source->pipeline), rtp_source->vsource, rtp_source->vfilter,
				rtp_source->vparser, rtp_source->parserfilter, rtp_source->vrtppay, rtp_source->vsink, NULL);
			
			if (gst_element_link_many (rtp_source->vsource, rtp_source->vfilter, rtp_source->vparser, rtp_source->parserfilter, rtp_source->vrtppay, rtp_source->vsink, NULL) != TRUE) {
				JANUS_LOG (LOG_ERR, "Failed to link GStreamer video elements\n");
				gst_object_unref (GST_OBJECT (rtp_source->pipeline));
				g_free(rtp_source);
				return;
			}
		} else if (session->send_audio && !session->send_video) {
			gst_bin_add_many (GST_BIN (rtp_source->pipeline), rtp_source->asource,
				rtp_source->resample, rtp_source->afilter, rtp_source->aencoder, rtp_source->artppay,
				rtp_source->asink, NULL);
			
			if (gst_element_link_many (rtp_source->asource, rtp_source->resample, rtp_source->afilter, rtp_source->aencoder, rtp_source->artppay, rtp_source->asink, NULL) != TRUE ) {
				JANUS_LOG (LOG_ERR, "Failed to link GStreamer audio elements\n");
				gst_object_unref (GST_OBJECT (rtp_source->pipeline));
				g_free(rtp_source);
				return;
			}
		} else {
			JANUS_LOG (LOG_VERB, "No audio or video requested in the media\n");
		}
		
		rtp_source->bus = gst_pipeline_get_bus(GST_PIPELINE(rtp_source->pipeline));
		session->rtp_source = rtp_source;
		
		GError * error = NULL;
		g_thread_try_new ("rtp_source", &janus_nativeclient_relay_thread, session, &error);
		if (error != NULL) {
			JANUS_LOG(LOG_ERR, "Got error %d (%s) trying to launch the RTP thread...\n", error->code, error->message ? error->message : "??");
			gst_object_unref (GST_OBJECT (rtp_source->pipeline));
			g_free(rtp_source);
			return;
		}
	}

	if (session->play_audio) {
		janus_nativeclient_audio_player * aplayer = (janus_nativeclient_audio_player *)g_malloc0(sizeof(janus_nativeclient_audio_player));
		if (aplayer == NULL) {
			JANUS_LOG (LOG_FATAL, "Memory error\n");
			/* FIXME: clean up session here, if pipeline fails */
			return;
		}
		aplayer->asource = gst_element_factory_make ("appsrc","asource");
		aplayer->afiltercaps = NULL;
		aplayer->isaCapsSet = FALSE;
		aplayer->artpdepay = gst_element_factory_make ("rtpopusdepay", "artpdepay");
		aplayer->adecoder = gst_element_factory_make ("opusdec", "adecoder");
		aplayer->aconvert = gst_element_factory_make ("audioconvert", "aconvert");
		aplayer->aresample = gst_element_factory_make ("audioresample", "aresample");
		aplayer->aoutput = gst_element_factory_make ("alsasink", "aoutput");
		aplayer->apipeline = gst_pipeline_new ("pipeline");
		g_object_set (aplayer->asource, "format", GST_FORMAT_TIME, NULL);
		g_object_set (aplayer->aoutput, "sync", FALSE, NULL);
		//g_object_set (aplayer->aoutput, "async", FALSE, NULL);
		gst_bin_add_many(GST_BIN(aplayer->apipeline), aplayer->asource, 
			aplayer->artpdepay, aplayer->adecoder, aplayer->aresample, aplayer->aconvert, aplayer->aoutput, NULL);
		if (gst_element_link_many (aplayer->asource, aplayer->artpdepay, aplayer->adecoder, aplayer->aresample, aplayer->aconvert, aplayer->aoutput, NULL) != TRUE) {
			JANUS_LOG (LOG_ERR, "Failed to link GSTREAMER elements in audio player!!!\n");
			gst_object_unref (GST_OBJECT(aplayer->apipeline));
			g_free (aplayer);
			/* FIXME: clean up session here, if pipeline fails */
			return;
		}
		aplayer->abus = gst_pipeline_get_bus (GST_PIPELINE (aplayer->apipeline));
		aplayer->last_received_audio = janus_get_monotonic_time();
		session->aplayer = aplayer;
		session->apackets = g_async_queue_new ();
		GError * error = NULL;
		g_thread_try_new ("playout", &janus_nativeclient_aplayer_thread, session, &error);
		if (error != NULL) {
			JANUS_LOG (LOG_ERR, "Got error %d (%s) trying to launch the gstreamer thread...\n", error->code, error->message ? error->message : "??");
			gst_object_unref (GST_OBJECT(aplayer->apipeline));
			g_free (aplayer);
		}
	}
		
	session->started = TRUE;
	return;
}

static void * janus_nativeclient_relay_thread (void * data) {
	janus_nativeclient_session * session = (janus_nativeclient_session *) data;
	if (session == NULL) {
		JANUS_LOG (LOG_ERR, "invalid session!\n");
		g_thread_unref (g_thread_self());
		return NULL; 
	}
	if (session->rtp_source == NULL) {
		JANUS_LOG (LOG_ERR, "Invalid gstreamer source pipeline..\n");
		g_thread_unref (g_thread_self());
		return NULL;
	}
	janus_nativeclient_rtp_source * source = session->rtp_source;
	gst_element_set_state (source->pipeline, GST_STATE_PLAYING);
	if (gst_element_get_state (source->pipeline, NULL, NULL, 500000000) == GST_STATE_CHANGE_FAILURE) {
		JANUS_LOG (LOG_ERR, "Unable to play rtp_source pipeline..!\n");
		session->started = FALSE;
		g_thread_unref (g_thread_self());
		return NULL;
	}
	
	GstSample * asample = NULL, *vsample = NULL;
	GstBuffer * abuffer, * vbuffer;
	gpointer aframedata, vframedata;
	gsize afsize, vfsize;
	char * atempbuffer, * vtempbuffer;
	//janus_helpmet_rtp_relay_packet apacket;
	//janus_helpmet_rtp_relay_packet vpacket;
	int bytes = 0;
	
	while (!g_atomic_int_get (&stopping) && g_atomic_int_get(&initialized) && !g_atomic_int_get(&session->hangingup)) {
		
		if (session->send_audio)
			asample = gst_app_sink_pull_sample (GST_APP_SINK (source->asink));
		
		if (asample != NULL) {
			abuffer = gst_sample_get_buffer (asample);
			gst_buffer_extract_dup (abuffer, 0, -1, &aframedata, &afsize);
			
			atempbuffer = (char *)g_malloc0(afsize);
			memcpy(atempbuffer, aframedata, afsize);
			g_free (aframedata);
			
			bytes = afsize; //gst_buffer_get_size (abuffer);
			gst_sample_unref (asample);
			if (!session->started) continue;
			
			if (gateway != NULL)
				gateway->relay_rtp(session->handle, 0, atempbuffer, bytes);
			
			g_free (atempbuffer);
		}
		
		if (session->send_video)
			vsample = gst_app_sink_pull_sample (GST_APP_SINK (source->vsink));
			
		if (vsample != NULL) {
			vbuffer = gst_sample_get_buffer (vsample);
			gst_buffer_extract_dup (vbuffer, 0, -1, &vframedata, &vfsize);
			
			vtempbuffer = (char *)g_malloc0(vfsize);
			memcpy(vtempbuffer, vframedata, vfsize);
			g_free (vframedata);
			
			bytes = vfsize; //gst_buffer_get_size (abuffer);
			gst_sample_unref (asample);
			if (!session->started) continue;
			
			if (gateway != NULL)
				gateway->relay_rtp(session->handle, 0, vtempbuffer, bytes);
			
			g_free (vtempbuffer);
		}
	}
	usleep(500000);
	
	gst_object_unref(source->bus);
	gst_element_set_state (source->pipeline, GST_STATE_NULL);
	if (gst_element_get_state (source->pipeline, NULL, NULL, GST_CLOCK_TIME_NONE) == GST_STATE_CHANGE_FAILURE) {
		JANUS_LOG (LOG_ERR, "Unable to stop GSTREAMER rtp source pipeline..!!\n");
	}
	gst_object_unref (GST_OBJECT(source->pipeline));
	session->send_video = FALSE;
	session->send_audio = FALSE;
	
	JANUS_LOG (LOG_VERB, "Leaving gstreamer rtp_source thread..\n");
	g_thread_unref (g_thread_self());
	return NULL;
}

void janus_nativeclient_incoming_rtp(janus_plugin_session *handle, int video, char *buf, int len) {
	if(handle == NULL || handle->stopped || g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return;
	if(gateway) {
		/* Honour the audio/video active flags */
		janus_nativeclient_session *session = (janus_nativeclient_session *)handle->plugin_handle;	
		if(!session) {
			JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
			return;
		}
		
		if(session->destroyed)
			return;
		if (session->started && session->aplayer && !video) {
			janus_audio_packet * pkt = (janus_audio_packet *)g_malloc0(sizeof(janus_audio_packet));
			if (pkt == NULL) {
				JANUS_LOG (LOG_FATAL, "Memory error!\n");
				return;
			}
			pkt->data = g_malloc0(len+1);
			memcpy(pkt->data, buf, len+1);
			*(buf+len) = '\0';
			pkt->length = len;
			pkt->is_video = video;
			
			if (session->apackets != NULL)
				g_async_queue_push (session->apackets, pkt);
		}
		return;
	}
}

static void * janus_nativeclient_aplayer_thread (void * data) {
	janus_nativeclient_session * session = (janus_nativeclient_session *) data;
	if (session == NULL) {
		JANUS_LOG (LOG_ERR, "invalid session!\n");
		g_thread_unref (g_thread_self());
		return NULL; 
	}
	if (session->aplayer == NULL) {
		JANUS_LOG (LOG_ERR, "Invalid gstreamer pipeline..\n");
		g_thread_unref (g_thread_self());
		return NULL;
	}
	janus_nativeclient_audio_player * player = session->aplayer;
	gst_element_set_state (player->apipeline, GST_STATE_PLAYING);
	if (gst_element_get_state (player->apipeline, NULL, NULL, 500000000) == GST_STATE_CHANGE_FAILURE) {
		JANUS_LOG (LOG_ERR, "Unable to play pipeline..!\n");
		//session->active = FALSE;
		g_thread_unref (g_thread_self());
		return NULL;
	}
	
	GstBuffer * feedbuffer;
	GstFlowReturn ret;
	janus_audio_packet * packet = NULL;
	JANUS_LOG (LOG_VERB, "Joining audio player thread..\n");
	while (!g_atomic_int_get (&stopping) && g_atomic_int_get(&initialized) && !g_atomic_int_get(&session->hangingup)) {
		packet = g_async_queue_pop (session->apackets);
		if (packet == NULL) continue;
		if ((packet == &eos_apacket)||(g_atomic_int_get(&session->hangingup))) {
			gst_app_src_end_of_stream (GST_APP_SRC(player->asource));
			break;
		}
		if (packet->data == NULL) continue;
		
		if (!player->isaCapsSet) {
			player->afiltercaps = gst_caps_new_simple ("application/x-rtp",
				"media", G_TYPE_STRING, "audio",
				"clock-rate", G_TYPE_INT, 48000,
				"encoding-name", G_TYPE_STRING, "OPUS",
				"payload", G_TYPE_INT, 111,
				NULL);
			g_object_set (player->asource, "caps", player->afiltercaps, NULL);
			gst_caps_unref (player->afiltercaps);
			player->isaCapsSet = TRUE;
		}
		
		feedbuffer = gst_buffer_new_wrapped (packet->data, packet->length);
		ret = gst_app_src_push_buffer (GST_APP_SRC(player->asource), feedbuffer);
		if (ret != GST_FLOW_OK) {
			JANUS_LOG (LOG_WARN, "Incoming rtp packet not pushed!!\n");
		}		
		
	}
	
	usleep(500000);
	
	gst_object_unref (player->abus);
	gst_element_set_state (player->apipeline, GST_STATE_NULL);
	if (gst_element_get_state (player->apipeline, NULL, NULL, GST_CLOCK_TIME_NONE) == GST_STATE_CHANGE_FAILURE) {
		JANUS_LOG (LOG_ERR, "Unable to stop GSTREAMER audio player..!!\n");
	}
	gst_object_unref (GST_OBJECT(player->apipeline));
	session->play_audio = FALSE;

	if (session->apackets != NULL)
		g_async_queue_unref (session->apackets);
	
	session->apackets = NULL; /* FIXME: is this really needed? */
	
	/* FIXME: Send EOS on the gstreamer pipeline */
	JANUS_LOG (LOG_VERB, "Leaving audio player thread..\n");
	g_thread_unref (g_thread_self());
	return NULL;
}

void janus_nativeclient_incoming_rtcp(janus_plugin_session *handle, int video, char *buf, int len) {
	if(handle == NULL || handle->stopped || g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return;
	if(gateway) {
		janus_nativeclient_session *session = (janus_nativeclient_session *)handle->plugin_handle;	
		if(!session) {
			JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
			return;
		}
		uint64_t bw = janus_rtcp_get_remb (buf, len);
		
		if ((bw > 1024 * 512) && (bw < 1024 * 2048)) {
			JANUS_LOG (LOG_VERB, "Requested bandwidth is: %"SCNu64" KBps...\n", bw);
		}
	}
}

void janus_nativeclient_incoming_data(janus_plugin_session *handle, char *buf, int len) {
	if(handle == NULL || handle->stopped || g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return;
	if(gateway) {
		janus_nativeclient_session *session = (janus_nativeclient_session *)handle->plugin_handle;	
		if(!session) {
			JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
			return;
		}
		
		if(session->destroyed)
			return;
		if(buf == NULL || len <= 0)
			return;
		char *text = g_malloc0(len+1);
		memcpy(text, buf, len);
		*(text+len) = '\0';
		JANUS_LOG(LOG_VERB, "Got a DataChannel message (%zu bytes): %s\n", strlen(text), text);
		
		g_free(text);
	}
}

void janus_nativeclient_slow_link(janus_plugin_session *handle, int uplink, int video) {
	/* The core is informing us that our peer got or sent too many NACKs, are we pushing media too hard? */
	if(handle == NULL || handle->stopped || g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return;
	janus_nativeclient_session *session = (janus_nativeclient_session *)handle->plugin_handle;	
	if(!session) {
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		return;
	}
	if(session->destroyed)
		return;
	
	return;
	/*session->slowlink_count++;
	if(uplink && !video && !session->audio_active) {
		// We're not relaying audio and the peer is expecting it, so NACKs are normal 
		JANUS_LOG(LOG_VERB, "Getting a lot of NACKs (slow uplink) for audio, but that's expected, a configure disabled the audio forwarding\n");
	} else if(uplink && video && !session->video_active) {
		// We're not relaying video and the peer is expecting it, so NACKs are normal 
		JANUS_LOG(LOG_VERB, "Getting a lot of NACKs (slow uplink) for video, but that's expected, a configure disabled the video forwarding\n");
	} else {
		// Slow uplink or downlink, maybe we set the bitrate cap too high? 
		if(video) {
			// Halve the bitrate, but don't go too low... 
			if(!uplink) {
				// Downlink issue, user has trouble sending, halve this user's bitrate cap 
				session->bitrate = session->bitrate > 0 ? session->bitrate : 512*1024;
				session->bitrate = session->bitrate/2;
				if(session->bitrate < 64*1024)
					session->bitrate = 64*1024;
			} else {
				// Uplink issue, user has trouble receiving, halve this user's peer's bitrate cap 
				if(session->peer == NULL || session->peer->handle == NULL)
					return;	
				session->peer->bitrate = session->peer->bitrate > 0 ? session->peer->bitrate : 512*1024;
				session->peer->bitrate = session->peer->bitrate/2;
				if(session->peer->bitrate < 64*1024)
					session->peer->bitrate = 64*1024;
			}
			JANUS_LOG(LOG_WARN, "Getting a lot of NACKs (slow %s) for %s, forcing a lower REMB: %"SCNu64"\n",
				uplink ? "uplink" : "downlink", video ? "video" : "audio", uplink ? session->peer->bitrate : session->bitrate);
			// ... and send a new REMB back 
			char rtcpbuf[24];
			janus_rtcp_remb((char *)(&rtcpbuf), 24, uplink ? session->peer->bitrate : session->bitrate);
			gateway->relay_rtcp(uplink ? session->peer->handle : handle, 1, rtcpbuf, 24);
			// As a last thing, notify the affected user about this 
			json_t *event = json_object();
			json_object_set_new(event, "nativeclient", json_string("event"));
			json_t *result = json_object();
			json_object_set_new(result, "status", json_string("slow_link"));
			json_object_set_new(result, "bitrate", json_integer(uplink ? session->peer->bitrate : session->bitrate));
			json_object_set_new(event, "result", result);
			gateway->push_event(uplink ? session->peer->handle : handle, &janus_nativeclient_plugin, NULL, event, NULL);
			json_decref(event);
		}
	}*/
}

void janus_nativeclient_hangup_media(janus_plugin_session *handle) {
	JANUS_LOG(LOG_INFO, "No WebRTC media anymore\n");
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return;
	janus_nativeclient_session *session = (janus_nativeclient_session *)handle->plugin_handle;	
	if(!session) {
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		return;
	}
	if(session->destroyed)
		return;
	
	if (session->apackets != NULL)
		g_async_queue_push(session->apackets, &eos_apacket);
		
	if(g_atomic_int_add(&session->hangingup, 1))
		return;
	
}

/* Thread to handle incoming messages */
static void *janus_nativeclient_handler(void *data) {
	JANUS_LOG(LOG_VERB, "Joining NativeClient handler thread\n");
	janus_nativeclient_message *msg = NULL;
	int error_code = 0;
	char error_cause[512];
	json_t *root = NULL;
	while(g_atomic_int_get(&initialized) && !g_atomic_int_get(&stopping)) {
		msg = g_async_queue_pop(messages);
		if(msg == NULL)
			continue;
		if(msg == &exit_message)
			break;
		if(msg->handle == NULL) {
			janus_nativeclient_message_free(msg);
			continue;
		}
		janus_nativeclient_session *session = (janus_nativeclient_session *)msg->handle->plugin_handle;
		if(!session) {
			JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
			janus_nativeclient_message_free(msg);
			continue;
		}
		if(session->destroyed) {
			janus_nativeclient_message_free(msg);
			continue;
		}
		/* Handle request */
		error_code = 0;
		root = msg->message;
		if(msg->message == NULL) {
			JANUS_LOG(LOG_ERR, "No message??\n");
			error_code = JANUS_NATIVECLIENT_ERROR_NO_MESSAGE;
			g_snprintf(error_cause, 512, "%s", "No message??");
			goto error;
		}
		if(!json_is_object(root)) {
			JANUS_LOG(LOG_ERR, "JSON error: not an object\n");
			error_code = JANUS_NATIVECLIENT_ERROR_INVALID_JSON;
			g_snprintf(error_cause, 512, "JSON error: not an object");
			goto error;
		}
		JANUS_VALIDATE_JSON_OBJECT(root, event_parameters,
			error_code, error_cause, TRUE,
			JANUS_NATIVECLIENT_ERROR_MISSING_ELEMENT, JANUS_NATIVECLIENT_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto error;
		const char *msg_sdp_type = json_string_value(json_object_get(msg->jsep, "type"));
		const char *msg_sdp = json_string_value(json_object_get(msg->jsep, "sdp"));
		json_t *event = json_object_get(root, "event");
		const char *event_text = json_string_value(event);
		
		json_t *result = NULL;
		char * sdp_type = NULL, *sdp = NULL;
		char * janus_text = NULL;
		
		if(!strcasecmp(event_text, "incomingcall")) {
			if (!msg_sdp) {
				JANUS_LOG (LOG_ERR, "Missing SDP Offer.\n");
				error_code = JANUS_NATIVECLIENT_ERROR_MISSING_SDP;
				g_snprintf(error_cause, 512, "Missing SDP offer");
				goto error;
			}
			/* We need to prepare an answer */
			int opus_pt = 111, vp8_pt = 97;
			
			char * opus_dir = NULL;
			char * vp8_dir = NULL;
			
			if(strstr(msg_sdp, "m=audio")) {
				opus_dir = janus_get_opus_dir (msg_sdp);
				JANUS_LOG (LOG_VERB, "Audio requested: direction is %s \n", opus_dir);
			}
			if(strstr(msg_sdp, "m=video")) {
				vp8_dir = janus_get_vp8_dir (msg_sdp);
				JANUS_LOG (LOG_VERB, "Video requested: direction is %s \n", vp8_dir);
			}
			sdp_type = "answer";
			char sdptemp[1024], audio_mline[256], video_mline[512], data_lines[256];
			if (opus_pt > 0 && opus_dir != NULL) {
				if (!strcasecmp(opus_dir, "sendrecv")) {
					g_snprintf(audio_mline, 256, sdp_a_template,
						opus_pt,						/* Opus payload type */
						"sendrecv",						/* FIXME to check a= line */
						opus_pt); 						/* Opus payload type */
					session->play_audio = TRUE;
					session->send_audio = TRUE;
				} else if (!strcasecmp(opus_dir,"sendonly")){
					g_snprintf(audio_mline, 256, sdp_a_template,
						opus_pt,						/* Opus payload type */
						"recvonly",						/* FIXME to check a= line */
						opus_pt); 						/* Opus payload type */
					session->play_audio = TRUE;
					session->send_audio = FALSE;
				} else if (!strcasecmp(opus_dir,"recvonly")){
					g_snprintf(audio_mline, 256, sdp_a_template,
						opus_pt,						/* Opus payload type */
						"sendonly",						/* FIXME to check a= line */
						opus_pt); 						/* Opus payload type */
					session->play_audio = FALSE;
					session->send_audio = TRUE;
				} else {
					g_snprintf(audio_mline, 256, sdp_a_template,
						opus_pt,						/* Opus payload type */
						"inactive",						/* FIXME to check a= line */
						opus_pt); 						/* Opus payload type */
					session->play_audio = FALSE;
					session->send_audio = FALSE;
				}
			} else {
				audio_mline[0] = '\0';
				session->play_audio = FALSE;
				session->send_audio = FALSE;
			}
			
			//if (vp8_pt > 0 && vp8_dir != NULL) {
				//if (!strcasecmp(vp8_dir, "sendrecv") || !strcasecmp(vp8_dir, "recvonly")) {
					g_snprintf(video_mline, 512, sdp_v_template,
						vp8_pt,							/* VP8 payload type */
						"sendonly",						/* FIXME to check a= line */
						vp8_pt, 						/* VP8 payload type */
						vp8_pt, 						/* VP8 payload type */
						"profile-level-id=42e028;level-asymmetry-allowed=1",
						vp8_pt, 						/* VP8 payload type */
						vp8_pt, 						/* VP8 payload type */
						vp8_pt, 						/* VP8 payload type */
						vp8_pt); 						/* VP8 payload type */
					session->send_video = TRUE;
				/*} else {
					g_snprintf(video_mline, 512, sdp_v_template,
						vp8_pt,							
						"inactive",						
						vp8_pt, 						
						vp8_pt, 						
						"profile-level-id=42e028;level-asymmetry-allowed=1",
						vp8_pt, 						
						vp8_pt, 						
						vp8_pt, 						
						vp8_pt); 						
					session->send_video = FALSE;
				}*/
			/*} else {
				video_mline[0] = '\0';
				session->send_video = FALSE;
			}*/
			
			/* Always offer to receive data */
			g_snprintf(data_lines, 512, 
				"m=application 1 DTLS/SCTP 5000\r\n"
				"c=IN IP4 1.1.1.1\r\n"
				"a=sctpmap:5000 webrtc-datachannel 16\r\n");
			
			g_snprintf(sdptemp, 1024, sdp_template,
				janus_get_real_time(),			/* We need current time here */
				janus_get_real_time(),			/* We need current time here */
				"PacketServo",		/* Playout session */
				audio_mline,					/* Audio m-line, if any */
				video_mline,					/* Video m-line, if any */
				data_lines);
			
			sdp = g_strdup(sdptemp);
			JANUS_LOG(LOG_VERB, "Going to answer this SDP:\n%s\n", sdp);
			
			result = json_object();
			json_object_set_new(result, "request", json_string("accept"));
			janus_text = "message";
		} else if(!strcasecmp(event_text, "accepted")) {
			JANUS_LOG (LOG_VERB, "Remote client accepted the call..\n");
			goto done;
			/*result = json_object();
			json_object_set_new (result, "completed", json_true());
			janus_text = "trickle";*/
		} else if(!strcasecmp(event_text, "hangup")) {
			JANUS_LOG (LOG_VERB, "Received a hangup request..\n");
			gateway->close_pc(session->handle);
			janus_text="hangup";
		} else if(!strcasecmp(event_text, "registered")) {
			JANUS_LOG (LOG_VERB, "Registration successful..\n");
			goto done;
		} else {
			JANUS_LOG(LOG_ERR, "Unknown event (%s)\n", event_text);
			error_code = JANUS_NATIVECLIENT_ERROR_INVALID_REQUEST;
			g_snprintf(error_cause, 512, "Unknown event (%s)", event_text);
			goto error;
		}

		/* Prepare JSON event */
		json_t *jsep = sdp ? json_pack("{ssss}", "type", sdp_type, "sdp", sdp) : NULL;
		int ret = gateway->send_request(msg->handle, &janus_nativeclient_plugin, msg->transaction, result, jsep, janus_text);
		JANUS_LOG(LOG_VERB, "  >> Sending request: %d (%s)\n", ret, janus_get_api_error(ret));
		g_free(sdp);
		if (result) json_decref(result);
		if(jsep)
			json_decref(jsep);
		janus_nativeclient_message_free(msg);
		continue;
		
error:
		{
			if (sdp) g_free(sdp);
			if (result) json_decref(result);
			JANUS_LOG(LOG_VERB, "  >> Pushing event: %d (%s)\n", -1, janus_get_api_error(-1));
			janus_nativeclient_message_free(msg);
			continue;
		}

done:
		{
			janus_nativeclient_message_free(msg);
		}
	}
	JANUS_LOG(LOG_VERB, "Leaving NativeClient handler thread\n");
	return NULL;
}
