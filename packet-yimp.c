#include "config.h"
#include <glib.h>
#include <glib/gprintf.h>

#if 0
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#endif

#include "ws_symbol_export.h"

#include <epan/conversation.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <yatewiresniff.h>


void proto_register_yimp(void);
void proto_reg_handoff_yimp(void);

/* Initialize TLV fields for UDP messages */
static int hf_yimp_tlv_result = -1;
static int hf_yimp_tlv_broadcast = -1;
static int hf_yimp_tlv_threadpointer = -1;
static int hf_yimp_tlv_threadname = -1;
static int hf_yimp_tlv_data = -1;
static int hf_yimp_tlv_final = -1;

/* Initialize the protocol and registered fields */
static int proto_yimp = -1;
static int hf_yimp_line = -1;
static int hf_yimp_tlv_type = -1;
static int hf_yimp_tlv_length = -1;
static int hf_yimp_tlv_dataremain = -1;
static int hf_yimp_output = -1;
static int hf_yimp_signature = -1;
static int hf_yimp_messagename = -1;
static int hf_yimp_role = -1;
static int hf_yimp_message = -1;
static int hf_yimp_handlers = -1;
static int hf_yimp_fulltext = -1;
static int hf_yimp_id = -1;
static int hf_yimp_time = -1;
static int hf_yimp_name = -1;
static int hf_yimp_command = -1;
static int hf_yimp_retvalue = -1;
static int hf_yimp_nodename = -1;
static int hf_yimp_test= -1;
static int hf_yimp_module = -1;
static int hf_yimp_server = -1;
static int hf_yimp_parameter = -1;
static int hf_yimp_tlvs = -1;
static int hf_yimp_element = -1;
static int hf_yimp_parameter_watch = -1;
static int hf_yimp_parameter_success = -1;
static int hf_yimp_install_priority = -1;
static int hf_yimp_parameter_value = -1;
static int hf_yimp_version = -1;
static int hf_yimp_status = -1;
static int hf_yimp_ping = -1;
static int hf_yimp_timestamp = -1;
static int hf_yimp_hash = -1;
static int hf_yimp_processed = -1;
static int hf_yimp_parameter_data = -1;
static int hf_yimp_data_columns = -1;
static int hf_yimp_data_lines = -1;
static int hf_yimp_continuation = -1;

static expert_field ei_yimp_empty_payload = EI_INIT;

/* option setable via preferences */
static gboolean yimp_heuristic = TRUE;

/* Initialize the subtree pointers */
static gint ett_yimp = -1;
static gint ett_yimp_tlv_header = -1;

static dissector_handle_t yimp_handle;

#define MAX_COLS 250
#define MAX_ROWS 10000
#define MAX_LINE_LENGTH 180
#define MAX_COL_LENGTH 10
#define MAX_BUFFER 2000

static const value_string yimp_tags_vals[] =
{
    { YSNIFF_RESULT, "Type of the encoded message"},
    { YSNIFF_THREAD_ADDR, "Pointer to the current thread"},
    { YSNIFF_THREAD_NAME, "Name of the current thread"},
    { YSNIFF_DATA, "Pointer to data"},
    { YSNIFF_BROADCAST, "Broadcast tag"},
    { YSNIFF_FINAL_TAG, "Final tag = 0"},
    
    {0, NULL}
    
};

typedef enum {
    SUBMITTED = 0,
    RETURNED = 1
}yimp_proceed_t;

static const value_string yimp_result[] = {
    { SUBMITTED, "Message submitted" },
    { RETURNED, "Message returned" },
    { 0,	NULL }
};

static const value_string yimp_broadcast[] = {
    { 0,	"No" },
    { 1,	"Yes" },
    { 0,	NULL }
};

/* Function used to unescape characters */
char* replace(char* str, char* a, char* b )
{   char *p = 0;
    int len  = 0;
    int lena = 0;
    int lenb = 0;
    
    len = strlen(str);
    lena = strlen(a);
    lenb = strlen(b);
    
    for (p = str; (p = strstr(p, a)); ++p) {
	if (lena  != lenb )
	    memmove(p+lenb, p+lena, len-(p - str));
	memcpy(p, b,lenb);
	
    }
    str[len] = '\0';
    return str ;
}

/* Find length of a PDU which ends in LF or in CRLF */
int
yimp_find_pdu_len(tvbuff_t *tvb, int offset)
{
    int start_offset=0;
    int end_offset = 0;
    
    start_offset = offset;
    
    end_offset = tvb_find_guint8(tvb, offset, -1, '\n');
    
    if (end_offset != -1) {
	return (end_offset - start_offset) + 1 ;
	
	if (tvb_get_guint8(tvb, end_offset + 1) == '\n')
	    return (end_offset - start_offset) + 2;
    }
    
    else
	return - 1;
}

/* Dissect TLV for UDP messages */
static int
dissect_tlvs(tvbuff_t *tvb, proto_tree *yimp_tree, int offset)
{
    guint8 tlv_type = 0;
    guint8 tlv_length = 0;
    int next_offset = 0;
    for (;;)
    {
	
	tlv_type = tvb_get_guint8(tvb, offset);
	tlv_length = tvb_get_guint8(tvb, offset + 1);
	
	offset += 2;
	
	switch (tlv_type) {
	    case YSNIFF_RESULT:
		next_offset = tlv_length;
		proto_tree_add_item(yimp_tree, hf_yimp_tlv_result, tvb, offset, next_offset, ENC_BIG_ENDIAN);
		offset += next_offset;
		break;
	    case YSNIFF_THREAD_ADDR:
		next_offset = tlv_length;
		proto_tree_add_item(yimp_tree, hf_yimp_tlv_threadpointer, tvb, offset, next_offset, ENC_BIG_ENDIAN);
		offset += next_offset;
		break;
	    case YSNIFF_THREAD_NAME:
		next_offset = tlv_length;
		proto_tree_add_item(yimp_tree, hf_yimp_tlv_threadname, tvb, offset, next_offset, ENC_BIG_ENDIAN );
		offset += next_offset;
		break;
	    case YSNIFF_DATA:
		next_offset = tlv_length;
		proto_tree_add_item(yimp_tree, hf_yimp_tlv_data, tvb, offset, next_offset, ENC_BIG_ENDIAN);
		offset += next_offset;
		break;
	    case YSNIFF_BROADCAST:
		next_offset = tlv_length;
		proto_tree_add_item(yimp_tree, hf_yimp_tlv_broadcast, tvb, offset, next_offset, ENC_BIG_ENDIAN);
		offset += next_offset;
		break;
	    case YSNIFF_FINAL_TAG:
		next_offset = tlv_length;
		offset += next_offset;
		
		return offset;
		
	}
	
    }
    
}

static gint
dissect_yimp_tcp_dispatch(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
    gint procent_offset = 0, length = 0;
    proto_item *ti;
    proto_tree *yimp_tree;
    gint value_offset = 0;
    proto_item *tlv_tree;
    gint line_end_offset = 0, semicolon_offset = 0;
    proto_tree *query_tree;
    int tokenlen = 0;
    int path_len = 0;
    const char *params = 0;
    gchar *query_str = 0, *parameter_str = 0;
    const char *name_str = 0;
    gchar *retvalue_str = 0;
    int query_str_len = 0, params_len = 0, query_offset = 0;
    int parameter_str_len = 0;
    gint linelen = 0, next_offset = 0;
    guint len_tvb = 0;
    
    len_tvb = yimp_find_pdu_len(tvb, offset);
    ti = proto_tree_add_protocol_format(tree, proto_yimp, tvb, 0, len_tvb, "Yate's Internal Messages Protocol (%d bytes)", len_tvb);
    yimp_tree = proto_item_add_subtree(ti, ett_yimp);
    
    procent_offset = tvb_find_guint8(tvb, offset, -1, ':');
    length = procent_offset - offset;
    proto_tree_add_item(yimp_tree, hf_yimp_command, tvb, offset, length, ENC_UTF_8|ENC_NA);
    offset = procent_offset + 1;
    
    procent_offset = tvb_find_guint8(tvb, offset, -1, ':');
    length = procent_offset - offset;
    proto_tree_add_item(yimp_tree, hf_yimp_id, tvb, offset, length, ENC_UTF_8|ENC_NA);
    offset = procent_offset + 1;
    
    procent_offset = tvb_find_guint8(tvb, offset, -1, ':');
    length = procent_offset - offset;
    proto_tree_add_item(yimp_tree, hf_yimp_processed, tvb, offset, length, ENC_UTF_8|ENC_NA);
    offset = procent_offset + 1;
    
    procent_offset = tvb_find_guint8(tvb, offset, -1, ':');
    length = procent_offset - offset;
    proto_tree_add_item(yimp_tree, hf_yimp_name, tvb, offset, length, ENC_UTF_8|ENC_NA);
    name_str = (const char *)tvb_get_string_enc(wmem_packet_scope(), tvb, offset, length, ENC_ASCII);
    col_append_fstr(pinfo->cinfo, COL_INFO, "Message:%s ", name_str);
    offset = procent_offset + 1;
    
    procent_offset = tvb_find_guint8(tvb, offset, -1, ':');
    length = procent_offset - offset;
    retvalue_str = (gchar *)tvb_get_string_enc(wmem_packet_scope(), tvb, offset, length, ENC_ASCII);
    replace(retvalue_str, "%J", " ");
    proto_tree_add_string(yimp_tree, hf_yimp_retvalue, tvb, offset,length, retvalue_str);
    offset = procent_offset;
    
    linelen = tvb_find_line_end(tvb, offset, -1, &next_offset, FALSE);
    if (linelen == 0) {
	
	offset = next_offset;
    }
    line_end_offset = offset + linelen;
    
    
    semicolon_offset = tvb_find_guint8(tvb, offset, linelen, ':');
    
    value_offset = tvb_skip_wsp(tvb, semicolon_offset, line_end_offset - (semicolon_offset + 1));
    
    tokenlen = line_end_offset - value_offset;
    
    params = (const char *)tvb_get_string_enc(wmem_packet_scope(), tvb, value_offset, tokenlen, ENC_UTF_8);
    
    tlv_tree = proto_tree_add_string(yimp_tree, hf_yimp_message, tvb, value_offset + 1, tokenlen, params);
    proto_item_set_text(tlv_tree, "PARAMETERS");
    if ((query_str = strchr(params, ':')) != NULL) {
	if (strlen(query_str) > 1) {
	    query_str ++;
	    query_str_len = (int)strlen(query_str);
	    
	    params_len = (int)strlen(params);
	    
	    path_len = params_len - query_str_len;
	    
	    query_offset = value_offset + path_len;
	    
	    query_tree = proto_item_add_subtree(tlv_tree, ett_yimp);
	    
	    for (parameter_str = strtok(query_str, ":"); parameter_str; parameter_str = strtok(NULL, ":")) {
		parameter_str_len = (int)strlen(parameter_str);
		replace(parameter_str, "%z"  , ":");
		proto_tree_add_string(query_tree, hf_yimp_parameter, tvb, query_offset, parameter_str_len, parameter_str);
		query_offset += parameter_str_len + 1;
		
	    }
	    
	    
	}
	
	
    }
    
    offset += len_tvb;
    return offset;
    
}


static gint
dissect_yimp_tcp_enque(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
    gint procent_offset = 0, length = 0;
    proto_item *ti;
    proto_tree *yimp_tree;
    gint value_offset = 0;
    proto_item *tlv_tree;
    gint line_end_offset = 0, semicolon_offset = 0;
    proto_tree *query_tree;
    int tokenlen = 0;
    int path_len = 0;
    const char *params = 0;
    gchar *query_str = 0, *parameter_str = 0, *retvalue_str = 0;
    const char *name_str = 0;
    int query_str_len = 0, params_len = 0, query_offset = 0;
    int parameter_str_len = 0;
    gint linelen = 0, next_offset = 0;
    guint len_tvb = 0;
    
    
    len_tvb = yimp_find_pdu_len(tvb, offset);
    ti = proto_tree_add_protocol_format(tree, proto_yimp, tvb, 0, len_tvb, "Yate's Internal Messages Protocol (%d bytes)", len_tvb);
    yimp_tree = proto_item_add_subtree(ti, ett_yimp);
    
    
    procent_offset = tvb_find_guint8(tvb, offset, -1, ':');
    length = procent_offset - offset;
    proto_tree_add_item(yimp_tree, hf_yimp_command, tvb, offset, length, ENC_UTF_8|ENC_NA);
    offset = procent_offset + 1;
    
    procent_offset = tvb_find_guint8(tvb, offset, -1, ':');
    length = procent_offset - offset;
    proto_tree_add_item(yimp_tree, hf_yimp_id, tvb, offset, length, ENC_UTF_8|ENC_NA);
    offset = procent_offset + 1;
    
    procent_offset = tvb_find_guint8(tvb, offset, -1, ':');
    length = procent_offset - offset;
    proto_tree_add_item(yimp_tree, hf_yimp_time, tvb, offset, length, ENC_UTF_8|ENC_NA);
    offset = procent_offset + 1;
    
    procent_offset = tvb_find_guint8(tvb, offset, -1, ':');
    length = procent_offset - offset;
    proto_tree_add_item(yimp_tree, hf_yimp_name, tvb, offset, length, ENC_UTF_8|ENC_NA);
    name_str = (const char *)tvb_get_string_enc(wmem_packet_scope(), tvb, offset, length, ENC_ASCII);
    col_append_fstr(pinfo->cinfo, COL_INFO, "Message:%s ", name_str);
    offset = procent_offset + 1;
    
    procent_offset = tvb_find_guint8(tvb, offset, -1, ':');
    length = procent_offset - offset;
    retvalue_str = (gchar *)tvb_get_string_enc(wmem_packet_scope(), tvb, offset, length, ENC_ASCII);
    replace(retvalue_str, "%J", " ");
    proto_tree_add_string(yimp_tree, hf_yimp_retvalue, tvb, offset,length, retvalue_str);
    offset = procent_offset;
    
    linelen = tvb_find_line_end(tvb, offset, -1, &next_offset, FALSE);
    if (linelen == 0) {
	
	offset = next_offset;
    }
    line_end_offset = offset + linelen;
    
    
    semicolon_offset = tvb_find_guint8(tvb, offset, linelen, ':');
    
    value_offset = tvb_skip_wsp(tvb, semicolon_offset, line_end_offset - (semicolon_offset + 1));
    
    tokenlen = line_end_offset - value_offset;
    
    params = (const char *)tvb_get_string_enc(wmem_packet_scope(), tvb, value_offset, tokenlen, ENC_ASCII);
    
    tlv_tree = proto_tree_add_string(yimp_tree, hf_yimp_message, tvb, value_offset + 1, tokenlen, params);
    proto_item_set_text(tlv_tree, "PARAMETERS");
    if ((query_str = strchr(params, ':')) != NULL) {
	if (strlen(query_str) > 1){
	    query_str ++;
	    query_str_len = (int)strlen(query_str);
	    
	    params_len = (int)strlen(params);
	    
	    path_len = params_len - query_str_len;
	    
	    query_offset = value_offset + path_len;
	    
	    query_tree = proto_item_add_subtree(tlv_tree, ett_yimp);
	    
	    for (parameter_str = strtok(query_str, ":"); parameter_str; parameter_str = strtok(NULL, ":"))
	    {
		parameter_str_len = (int)strlen(parameter_str);
		replace(parameter_str, "%z"  , ":");
		proto_tree_add_string(query_tree, hf_yimp_parameter, tvb, query_offset,            parameter_str_len, parameter_str);
		query_offset += parameter_str_len + 1;
	    }
	    
	    
	}
	
	
    }
    
    offset += len_tvb;
    return offset;
    
    
    
}

static void
dissect_output(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,  gint offset)
{
    gint procent_offset = 0;
    guint len_tvb = 0;
    proto_item *ti;
    proto_tree *yimp_tree;
    gint length = 0;
    gint line_end_offset = 0;
    const char *success_str = 0;
    gint linelen, next_offset = 0;
    
    len_tvb = yimp_find_pdu_len(tvb, offset);
    ti = proto_tree_add_protocol_format(tree, proto_yimp, tvb, 0, -1, "Yate's Internal Messages Protocol (%d bytes)",len_tvb);
    yimp_tree = proto_item_add_subtree(ti, ett_yimp);
    
    procent_offset = tvb_find_guint8(tvb, offset, -1, ':');
    length = procent_offset - offset;
    proto_tree_add_item(yimp_tree, hf_yimp_command, tvb, offset, length, ENC_UTF_8|ENC_NA);
    offset = procent_offset + 1;
    
    
    linelen = tvb_find_line_end(tvb, offset, -1, &next_offset, FALSE);
    line_end_offset = offset + linelen;
    
    length = line_end_offset - offset;
    
    proto_tree_add_item(yimp_tree, hf_yimp_output, tvb, offset, length, ENC_UTF_8|ENC_NA );
    success_str = (const char *)tvb_get_string_enc(wmem_packet_scope(), tvb, offset, length, ENC_ASCII);
    col_append_fstr(pinfo->cinfo, COL_INFO, "Output: %s ", success_str);
    
    offset += len_tvb;
    
}

static gint
dissect_yimp_watch_dispatch(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
    gint procent_offset = 0;
    guint len_tvb = 0;
    proto_item *ti;
    proto_tree *yimp_tree;
    gint length = 0;
    gint value_offset = 0;
    gint line_end_offset = 0, semicolon_offset = 0;
    proto_tree *query_tree;
    int tokenlen = 0;
    int path_len = 0;
    const char *params = 0;
    gchar *query_str = 0;
    const char *success_str = 0;
    int query_str_len = 0, params_len = 0, query_offset = 0;
    gint linelen = 0, next_offset = 0;
    
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "YIMP");
    len_tvb = yimp_find_pdu_len(tvb, offset);
    ti = proto_tree_add_protocol_format(tree, proto_yimp, tvb, 0, -1, "Yate's Internal Messages Protocol (%d bytes)",len_tvb);
    yimp_tree = proto_item_add_subtree(ti, ett_yimp);
    
    procent_offset = tvb_find_guint8(tvb, offset, -1, ':');
    length = procent_offset - offset;
    proto_tree_add_item(yimp_tree, hf_yimp_command, tvb, offset, length, ENC_UTF_8|ENC_NA);
    offset = procent_offset + 1;
    
    procent_offset = tvb_find_guint8(tvb, offset, -1, ':');
    length = procent_offset - offset;
    proto_tree_add_item(yimp_tree, hf_yimp_parameter_watch, tvb, offset, length, ENC_UTF_8|ENC_NA);
    success_str = (const char *)tvb_get_string_enc(wmem_packet_scope(), tvb, offset, length, ENC_ASCII);
    col_append_fstr(pinfo->cinfo, COL_INFO, "Watch: %s ", success_str);
    
    
    linelen = tvb_find_line_end(tvb, offset, -1, &next_offset, FALSE);
    if (linelen == 0) {
	
	offset = next_offset;
    }
    line_end_offset = offset + linelen;
    
    
    semicolon_offset = tvb_find_guint8(tvb, offset, linelen, ':');
    
    value_offset = tvb_skip_wsp(tvb, semicolon_offset, line_end_offset - (semicolon_offset + 1));
    
    tokenlen = line_end_offset - value_offset;
    
    params = (const char *)tvb_get_string_enc(wmem_packet_scope(), tvb, value_offset, tokenlen, ENC_ASCII);
    
    if ((query_str = strchr(params, ':')) != NULL) {
	if (strlen(query_str) > 1){
	    query_str ++;
	    query_str_len = (int)strlen(query_str);
	    
	    params_len = (int)strlen(params);
	    
	    path_len = params_len - query_str_len;
	    
	    query_offset = value_offset + path_len;
	    
	    query_tree = proto_item_add_subtree(yimp_tree, ett_yimp);
	    
	    proto_tree_add_string(query_tree, hf_yimp_parameter_success, tvb, query_offset, query_str_len, query_str);
	    
	    
	}
    }
    
    offset += len_tvb;
    return offset;
    
}

static gint
dissect_yimp_watch_enque(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset, void *data _U_)
{
    guint len_tvb = 0;
    proto_item *ti;
    proto_tree *yimp_tree;
    gint value_offset = 0;
    gint line_end_offset = 0, semicolon_offset = 0;
    proto_tree *query_tree;
    int tokenlen = 0;
    int path_len = 0;
    const char *params = 0;
    gchar *query_str = 0;
    int query_str_len = 0, params_len = 0, query_offset = 0;
    gint linelen = 0, next_offset = 0;
    gint procent_offset = 0;
    gint length = 0;
    
    len_tvb = yimp_find_pdu_len(tvb, offset);
    ti = proto_tree_add_protocol_format(tree, proto_yimp, tvb, 0, -1, "Yate's Internal Messages Protocol (%d bytes)",len_tvb);
    yimp_tree = proto_item_add_subtree(ti, ett_yimp);
    
    procent_offset = tvb_find_guint8(tvb, offset, -1, ':');
    length = procent_offset - offset;
    proto_tree_add_item(yimp_tree, hf_yimp_command, tvb, offset, length, ENC_UTF_8|ENC_NA);
    offset = procent_offset + 1;
    
    linelen = tvb_find_line_end(tvb, offset, -1, &next_offset, FALSE);
    if (linelen == 0) {
	
	offset = next_offset;
    }
    line_end_offset = offset + linelen;
    
    
    semicolon_offset = tvb_find_guint8(tvb, offset, linelen, ':');
    
    value_offset = tvb_skip_wsp(tvb, semicolon_offset, line_end_offset - (semicolon_offset + 1));
    
    tokenlen = line_end_offset - value_offset;
    
    params = (const char *)tvb_get_string_enc(wmem_packet_scope(), tvb, value_offset, tokenlen, ENC_ASCII);
    
    if ((query_str = strchr(params, ':')) != NULL) {
	if (strlen(query_str) > 1){
	    query_str ++;
	    query_str_len = (int)strlen(query_str);
	    
	    params_len = (int)strlen(params);
	    
	    path_len = params_len - query_str_len;
	    
	    query_offset = value_offset + path_len;
	    
	    query_tree = proto_item_add_subtree(yimp_tree, ett_yimp);
	    
	    proto_tree_add_string(query_tree, hf_yimp_parameter_watch, tvb, query_offset, query_str_len, query_str);
	    
	    col_add_fstr(pinfo->cinfo, COL_INFO, "Watch: %s ", query_str);
	    
	}
    }
    offset += len_tvb;
    return offset;
}

static gint
dissect_install_dispatch(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset, void *data _U_)
{
    
    gint procent_offset = 0;
    guint len_tvb = 0;
    proto_item *ti;
    proto_tree *yimp_tree;
    gint length = 0;
    gint value_offset = 0;
    gint line_end_offset = 0, semicolon_offset = 0;
    proto_tree *query_tree;
    int tokenlen = 0;
    int path_len = 0;
    const char *params = 0;
    gchar *query_str = 0;
    const char *success_str = 0;
    int query_str_len = 0, params_len = 0, query_offset = 0;
    gint linelen = 0, next_offset = 0;
    
    len_tvb = yimp_find_pdu_len(tvb, offset);
    ti = proto_tree_add_protocol_format(tree, proto_yimp, tvb, 0, -1, "Yate's Internal Messages Protocol (%d bytes)",len_tvb);
    yimp_tree = proto_item_add_subtree(ti, ett_yimp);
    
    procent_offset = tvb_find_guint8(tvb, offset, -1, ':');
    length = procent_offset - offset;
    proto_tree_add_item(yimp_tree, hf_yimp_command, tvb, offset, length, ENC_UTF_8|ENC_NA);
    offset = procent_offset + 1;
    
    procent_offset = tvb_find_guint8(tvb, offset, -1, ':');
    length = procent_offset - offset;
    proto_tree_add_item(yimp_tree, hf_yimp_install_priority, tvb, offset, length, ENC_UTF_8|ENC_NA);
    offset = procent_offset + 1;
    
    procent_offset = tvb_find_guint8(tvb, offset, -1, ':');
    length = procent_offset - offset;
    proto_tree_add_item(yimp_tree, hf_yimp_name, tvb, offset, length, ENC_UTF_8|ENC_NA);
    success_str = (const char *)tvb_get_string_enc(wmem_packet_scope(), tvb, offset, length, ENC_ASCII);
    col_add_fstr(pinfo->cinfo, COL_INFO, "Install: %s", success_str);
    
    
    linelen = tvb_find_line_end(tvb, offset, -1, &next_offset, FALSE);
    if (linelen == 0) {
	
	offset = next_offset;
    }
    line_end_offset = offset + linelen;
    
    
    semicolon_offset = tvb_find_guint8(tvb, offset, linelen, ':');
    
    value_offset = tvb_skip_wsp(tvb, semicolon_offset, line_end_offset - (semicolon_offset + 1));
    
    tokenlen = line_end_offset - value_offset;
    
    params = (const char *)tvb_get_string_enc(wmem_packet_scope(), tvb, value_offset, tokenlen, ENC_ASCII);
    
    if ((query_str = strchr(params, ':')) != NULL) {
	if (strlen(query_str) > 1){
	    query_str ++;
	    query_str_len = (int)strlen(query_str);
	    
	    params_len = (int)strlen(params);
	    
	    path_len = params_len - query_str_len;
	    
	    query_offset = value_offset + path_len;
	    
	    query_tree = proto_item_add_subtree(yimp_tree, ett_yimp);
	    
	    proto_tree_add_string(query_tree, hf_yimp_parameter_success, tvb, query_offset, query_str_len, query_str);
	    
	    return (TRUE);
	}
    }
    
    offset += len_tvb;
    return offset;
    
}

static gint
dissect_install_enque(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset, void *data _U_)
{
    
    gint procent_offset = 0;
    guint len_tvb = 0;
    proto_item *ti;
    proto_tree *yimp_tree;
    gint length = 0;
    gint value_offset = 0;
    gint line_end_offset = 0, semicolon_offset = 0;
    proto_tree *query_tree;
    int tokenlen = 0;
    int path_len = 0;
    const char *params = 0;
    gchar *name_str = 0;
    int query_str_len = 0, params_len = 0, query_offset = 0;
    gint linelen = 0, next_offset = 0;
    
    len_tvb = yimp_find_pdu_len(tvb, offset);
    ti = proto_tree_add_protocol_format(tree, proto_yimp, tvb, 0, -1, "Yate's Internal Messages Protocol (%d bytes)",len_tvb);
    yimp_tree = proto_item_add_subtree(ti, ett_yimp);
    
    procent_offset = tvb_find_guint8(tvb, offset, -1, ':');
    length = procent_offset - offset;
    proto_tree_add_item(yimp_tree, hf_yimp_command, tvb, offset, length, ENC_UTF_8|ENC_NA);
    offset = procent_offset + 1;
    
    procent_offset = tvb_find_guint8(tvb, offset, -1, ':');
    length = procent_offset - offset;
    proto_tree_add_item(yimp_tree, hf_yimp_install_priority, tvb, offset, length, ENC_UTF_8|ENC_NA);
    
    linelen = tvb_find_line_end(tvb, offset, -1, &next_offset, FALSE);
    if (linelen == 0) {
	
	offset = next_offset;
    }
    line_end_offset = offset + linelen;
    
    semicolon_offset = tvb_find_guint8(tvb, offset, linelen, ':');
    
    value_offset = tvb_skip_wsp(tvb, semicolon_offset, line_end_offset - (semicolon_offset + 1));
    
    tokenlen = line_end_offset - value_offset;
    
    params = (const char *)tvb_get_string_enc(wmem_packet_scope(), tvb, value_offset, tokenlen, ENC_ASCII);
    
    if ((name_str = strchr(params, ':')) != NULL) {
	if (strlen(name_str) > 1) {
	    name_str ++;
	    query_str_len = (int)strlen(name_str);
	    
	    params_len = (int)strlen(params);
	    
	    path_len = params_len - query_str_len;
	    
	    query_offset = value_offset + path_len;
	    
	    query_tree = proto_item_add_subtree(yimp_tree, ett_yimp);
	    
	    proto_tree_add_string(query_tree, hf_yimp_name, tvb, query_offset, query_str_len, name_str);
	    
	    col_add_fstr(pinfo->cinfo, COL_INFO, "Install: %s ", name_str);
	    return (TRUE);
	}
    }
    
    offset += len_tvb;
    return offset;
    
}

static gint
dissect_yimp_auth(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset, void *data _U_)
{
    gint procent_offset = 0;
    guint len_tvb = 0;
    proto_item *ti;
    proto_tree *yimp_tree;
    gint length = 0;
    gint value_offset = 0;
    gint line_end_offset = 0, semicolon_offset = 0;
    proto_tree *query_tree;
    int tokenlen = 0;
    int path_len = 0;
    const char *params = 0;
    gchar *query_str = 0;
    const char *success_str = 0;
    int query_str_len = 0, params_len = 0, query_offset = 0;
    gint linelen = 0, next_offset = 0;
    
    
    len_tvb = yimp_find_pdu_len(tvb, offset);
    ti = proto_tree_add_protocol_format(tree, proto_yimp, tvb, 0, -1, "Yate's Internal Messages Protocol (%d bytes)",len_tvb);
    yimp_tree = proto_item_add_subtree(ti, ett_yimp);
    
    linelen = tvb_find_line_end(tvb, offset, -1, &next_offset, FALSE);
    if (linelen == 0) {
	
	offset = next_offset;
    }
    line_end_offset = offset + linelen;
    
    procent_offset = tvb_find_guint8(tvb, offset, -1, ':');
    length = procent_offset - offset;
    proto_tree_add_item(yimp_tree, hf_yimp_command, tvb, offset, length, ENC_UTF_8|ENC_NA);
    offset = procent_offset + 1;
    
    procent_offset = tvb_find_guint8(tvb, offset, -1, ':');
    length = procent_offset - offset;
    proto_tree_add_item(yimp_tree, hf_yimp_timestamp, tvb, offset, length, ENC_UTF_8|ENC_NA);
    success_str = (const char *)tvb_get_string_enc(wmem_packet_scope(), tvb, offset, length, ENC_ASCII);
    col_append_fstr(pinfo->cinfo, COL_INFO, "Auth: %s ", success_str);
    
    linelen = tvb_find_line_end(tvb, offset, -1, &next_offset, FALSE);
    if (linelen == 0) {
	
	offset = next_offset;
    }
    line_end_offset = offset + linelen;
    
    
    semicolon_offset = tvb_find_guint8(tvb, offset, linelen, ':');
    
    value_offset = tvb_skip_wsp(tvb, semicolon_offset, line_end_offset - (semicolon_offset + 1));
    
    tokenlen = line_end_offset - value_offset;
    
    params = (const char *)tvb_get_string_enc(wmem_packet_scope(), tvb, value_offset, tokenlen, ENC_ASCII);
    
    if ((query_str = strchr(params, ':')) != NULL) {
	if (strlen(query_str) > 1) {
	    query_str ++;
	    query_str_len = (int)strlen(query_str);
	    
	    params_len = (int)strlen(params);
	    
	    path_len = params_len - query_str_len;
	    
	    query_offset = value_offset + path_len;
	    
	    query_tree = proto_item_add_subtree(yimp_tree, ett_yimp);
	    
	    
	    proto_tree_add_string(query_tree, hf_yimp_hash, tvb, query_offset, query_str_len, query_str);
	    
	    query_offset += query_str_len + 1;
	}
    }
    
    offset += len_tvb;
    return offset;
}


static void
dissect_yimp_quit(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    
    gint procent_offset = 0;
    guint len_tvb = 0;
    proto_item *ti;
    proto_tree *yimp_tree;
    gint length = 0;
    
    col_append_fstr(pinfo->cinfo, COL_INFO, "Quit ");
    len_tvb = yimp_find_pdu_len(tvb, offset);
    ti = proto_tree_add_protocol_format(tree, proto_yimp, tvb, 0, -1, "Yate's Internal Messages Protocol (%d bytes)",len_tvb);
    yimp_tree = proto_item_add_subtree(ti, ett_yimp);
    
    
    procent_offset = tvb_find_guint8(tvb, offset, -1, '\n');
    length = procent_offset - offset;
    proto_tree_add_item(yimp_tree, hf_yimp_command, tvb, offset, length, ENC_UTF_8|ENC_NA);
    
    offset = procent_offset + 1;
    
}


static gint
dissect_version(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset, void *data _U_)
{
    
    guint len_tvb = 0;
    proto_item *ti;
    proto_tree *yimp_tree;
    gint line_end_offset = 0, semicolon_offset = 0;
    proto_tree *query_tree;
    int tokenlen = 0;
    int path_len = 0;
    const char *params = 0;
    gchar *query_str = 0;
    int query_str_len = 0, params_len = 0, query_offset = 0;
    gint linelen = 0, next_offset = 0;
    gint procent_offset = 0;
    gint length = 0;
    
    len_tvb = yimp_find_pdu_len(tvb, offset);
    ti = proto_tree_add_protocol_format(tree, proto_yimp, tvb, 0, len_tvb, "Yate's Internal Messages Protocol (%d bytes)",len_tvb);
    yimp_tree = proto_item_add_subtree(ti, ett_yimp);
    
    procent_offset = tvb_find_guint8(tvb, offset, -1, ':');
    length = procent_offset - offset;
    proto_tree_add_item(yimp_tree, hf_yimp_command, tvb, offset, length, ENC_UTF_8|ENC_NA);
    
    linelen = tvb_find_line_end(tvb, offset, -1, &next_offset, FALSE);
    if (linelen == 0) {
	
	offset = next_offset;
    }
    line_end_offset = offset + linelen;
    
    
    semicolon_offset = tvb_find_guint8(tvb, offset, linelen, ':');
    
    tokenlen = line_end_offset - semicolon_offset;
    
    params = (const char *)tvb_get_string_enc(wmem_packet_scope(), tvb, semicolon_offset, tokenlen, ENC_ASCII);
    
    if ((query_str = strchr(params, ':')) != NULL) {
	if (strlen(query_str) > 1) {
	    query_str ++;
	    query_str_len = (int)strlen(query_str);
	    
	    params_len = (int)strlen(params);
	    
	    path_len = params_len - query_str_len;
	    
	    query_offset = semicolon_offset + path_len;
	    
	    query_tree = proto_item_add_subtree(yimp_tree, ett_yimp);
	    
	    proto_tree_add_string(query_tree, hf_yimp_version, tvb, query_offset, query_str_len, query_str);
	    query_offset += query_str_len + 1;
	    
	    col_append_fstr(pinfo->cinfo, COL_INFO, "Version: %s ", query_str);
	    
	    
	}
    }
    
    offset += len_tvb;
    return offset;
}

static gint
dissect_setlocal_enque(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset, void *data _U_)
{
    gint procent_offset = 0;
    guint len_tvb = 0;
    proto_item *ti;
    proto_tree *yimp_tree;
    gint length = 0;
    gint value_offset = 0;
    gint line_end_offset = 0, semicolon_offset = 0;
    proto_tree *query_tree;
    int tokenlen = 0;
    int path_len = 0;
    const char *params = 0;
    gchar *query_str = 0;
    const char *success_str = 0;
    int query_str_len = 0, params_len = 0, query_offset = 0;
    gint linelen = 0, next_offset = 0;
    
    len_tvb = yimp_find_pdu_len(tvb, offset);
    ti = proto_tree_add_protocol_format(tree, proto_yimp, tvb, 0, -1, "Yate's Internal Messages Protocol (%d bytes)",len_tvb);
    yimp_tree = proto_item_add_subtree(ti, ett_yimp);
    
    procent_offset = tvb_find_guint8(tvb, offset, -1, ':');
    length = procent_offset - offset;
    proto_tree_add_item(yimp_tree, hf_yimp_command, tvb, offset, length, ENC_UTF_8|ENC_NA);
    offset = procent_offset + 1;
    
    procent_offset = tvb_find_guint8(tvb, offset, -1, ':');
    length = procent_offset - offset;
    proto_tree_add_item(yimp_tree, hf_yimp_name, tvb, offset, length, ENC_UTF_8|ENC_NA);
    success_str = (const char *)tvb_get_string_enc(wmem_packet_scope(), tvb, offset, length, ENC_ASCII);
    col_add_fstr(pinfo->cinfo, COL_INFO, "Setlocal:%s  ", success_str);
    
    linelen = tvb_find_line_end(tvb, offset, -1, &next_offset, FALSE);
    if (linelen == 0) {
	
	offset = next_offset;
    }
    line_end_offset = offset + linelen;
    
    
    semicolon_offset = tvb_find_guint8(tvb, offset, linelen, ':');
    
    value_offset = tvb_skip_wsp(tvb, semicolon_offset, line_end_offset - (semicolon_offset + 1));
    
    tokenlen = line_end_offset - value_offset;
    
    params = (const char *)tvb_get_string_enc(wmem_packet_scope(), tvb, value_offset, tokenlen, ENC_ASCII);
    
    if ((query_str = strchr(params, ':')) != NULL) {
	if (strlen(query_str) > 1) {
	    query_str ++;
	    query_str_len = (int)strlen(query_str);
	    
	    params_len = (int)strlen(params);
	    
	    path_len = params_len - query_str_len;
	    
	    query_offset = value_offset + path_len;
	    
	    query_tree = proto_item_add_subtree(yimp_tree, ett_yimp);
	    
	    proto_tree_add_string(query_tree, hf_yimp_parameter_value, tvb, query_offset, query_str_len, query_str);
	    
	    
	}
    }
    offset += len_tvb;
    return offset;
}

static gint
dissect_yimp_status(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset, void *data _U_)
{
    
    guint len_tvb = 0;
    proto_item *ti;
    proto_tree *yimp_tree;
    gint value_offset = 0;
    gint line_end_offset = 0, semicolon_offset = 0;
    proto_tree *query_tree;
    int tokenlen = 0;
    int path_len = 0;
    const char *params = 0;
    gchar *query_str = 0;
    int query_str_len = 0, params_len = 0, query_offset = 0;
    gint linelen = 0, next_offset = 0;
    gint procent_offset = 0;
    gint length = 0;
    
    len_tvb = yimp_find_pdu_len(tvb, offset);
    ti = proto_tree_add_protocol_format(tree, proto_yimp, tvb, 0, -1, "Yate's Internal Messages Protocol (%d bytes)",len_tvb);
    yimp_tree = proto_item_add_subtree(ti, ett_yimp);
    
    procent_offset = tvb_find_guint8(tvb, offset, -1, ':');
    length = procent_offset - offset;
    proto_tree_add_item(yimp_tree, hf_yimp_command, tvb, offset, length, ENC_UTF_8|ENC_NA);
    offset = procent_offset + 1;
    
    linelen = tvb_find_line_end(tvb, offset, -1, &next_offset, FALSE);
    if (linelen == 0) {
	
	offset = next_offset;
    }
    line_end_offset = offset + linelen;
    
    
    semicolon_offset = tvb_find_guint8(tvb, offset, linelen, ':');
    
    value_offset = tvb_skip_wsp(tvb, semicolon_offset, line_end_offset - (semicolon_offset + 1));
    
    tokenlen = line_end_offset - value_offset;
    
    params = (const char *)tvb_get_string_enc(wmem_packet_scope(), tvb, value_offset, tokenlen, ENC_ASCII);
    
    if ((query_str = strchr(params, ':')) != NULL) {
	if (strlen(query_str) > 1) {
	    query_str ++;
	    query_str_len = (int)strlen(query_str);
	    
	    params_len = (int)strlen(params);
	    
	    path_len = params_len - query_str_len;
	    
	    query_offset = value_offset + path_len;
	    
	    query_tree = proto_item_add_subtree(yimp_tree, ett_yimp);
	    
	    proto_tree_add_string(query_tree, hf_yimp_status, tvb, query_offset, query_str_len, query_str);
	    
	    col_add_fstr(pinfo->cinfo, COL_INFO, "Status: %s ", query_str);
	    return (TRUE);
	}
    }
    
    offset += len_tvb;
    return offset;
}

static gint
dissect_yimp_ping(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset, void *data _U_)
{
    guint len_tvb = 0;
    proto_item *ti;
    proto_tree *yimp_tree;
    gint value_offset = 0;
    gint line_end_offset = 0, semicolon_offset = 0;
    proto_tree *query_tree;
    int tokenlen = 0;
    int path_len = 0;
    const char *params = 0;
    gchar *query_str = 0;
    int query_str_len = 0, params_len = 0, query_offset = 0;
    gint linelen = 0, next_offset = 0;
    gint procent_offset = 0;
    gint length = 0;
    
    len_tvb = yimp_find_pdu_len(tvb, offset);
    ti = proto_tree_add_protocol_format(tree, proto_yimp, tvb, 0, -1, "Yate's Internal Messages Protocol (%d bytes)",len_tvb);
    yimp_tree = proto_item_add_subtree(ti, ett_yimp);
    
    procent_offset = tvb_find_guint8(tvb, offset, -1, ':');
    length = procent_offset - offset;
    proto_tree_add_item(yimp_tree, hf_yimp_command, tvb, offset, length, ENC_UTF_8|ENC_NA);
    offset = procent_offset + 1;
    
    linelen = tvb_find_line_end(tvb, offset, -1, &next_offset, FALSE);
    if (linelen == 0) {
	
	offset = next_offset;
    }
    line_end_offset = offset + linelen;
    
    semicolon_offset = tvb_find_guint8(tvb, offset, linelen, ':');
    
    value_offset = tvb_skip_wsp(tvb, semicolon_offset, line_end_offset - (semicolon_offset + 1));
    
    tokenlen = line_end_offset - value_offset;
    
    params = (const char *)tvb_get_string_enc(wmem_packet_scope(), tvb, value_offset, tokenlen, ENC_ASCII);
    
    if ((query_str = strchr(params, ':')) != NULL) {
	if (strlen(query_str) > 1) {
	    query_str ++;
	    query_str_len = (int)strlen(query_str);
	    
	    params_len = (int)strlen(params);
	    
	    path_len = params_len - query_str_len;
	    
	    query_offset = value_offset + path_len;
	    
	    query_tree = proto_item_add_subtree(yimp_tree, ett_yimp);
	    proto_tree_add_string(query_tree, hf_yimp_ping, tvb, query_offset, query_str_len, query_str);
	    
	    col_add_fstr(pinfo->cinfo, COL_INFO, "Ping: %s ", query_str);
	    return (TRUE);
	}
    }
    
    offset += len_tvb;
    return offset;
}


static gint
dissect_yimp_uninstall_dispatch(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset, void *data _U_)
{
    gint procent_offset = 0;
    guint len_tvb = 0;
    proto_item *ti;
    proto_tree *yimp_tree;
    gint length = 0;
    gint value_offset = 0;
    gint line_end_offset = 0, semicolon_offset = 0;
    proto_tree *query_tree;
    int tokenlen = 0;
    int path_len = 0;
    const char *params = 0;
    gchar *query_str = 0;
    const char *success_str = 0;
    int query_str_len = 0, params_len = 0, query_offset = 0;
    gint linelen = 0, next_offset = 0;
    
    len_tvb = yimp_find_pdu_len(tvb, offset);
    ti = proto_tree_add_protocol_format(tree, proto_yimp, tvb, 0, -1, "Yate's Internal Messages Protocol (%d bytes)",len_tvb);
    yimp_tree = proto_item_add_subtree(ti, ett_yimp);
    
    linelen = tvb_find_line_end(tvb, offset, -1, &next_offset, FALSE);
    if (linelen == 0) {
	
	offset = next_offset;
    }
    line_end_offset = offset + linelen;
    
    procent_offset = tvb_find_guint8(tvb, offset, -1, ':');
    length = procent_offset - offset;
    proto_tree_add_item(yimp_tree, hf_yimp_command, tvb, offset, length, ENC_UTF_8|ENC_NA);
    offset = procent_offset + 1;
    
    procent_offset = tvb_find_guint8(tvb, offset, -1, ':');
    length = procent_offset - offset;
    proto_tree_add_item(yimp_tree, hf_yimp_install_priority, tvb, offset, length, ENC_UTF_8|ENC_NA);
    offset = procent_offset + 1;
    
    procent_offset = tvb_find_guint8(tvb, offset, -1, ':');
    length = procent_offset - offset;
    proto_tree_add_item(yimp_tree, hf_yimp_name, tvb, offset, length, ENC_UTF_8|ENC_NA);
    success_str = (const char*)tvb_get_string_enc(wmem_packet_scope(), tvb, offset, length, ENC_ASCII);
    col_add_fstr(pinfo->cinfo, COL_INFO, "Uninstall:%s ", success_str);
    
    
    linelen = tvb_find_line_end(tvb, offset, -1, &next_offset, FALSE);
    if (linelen == 0) {
	
	offset = next_offset;
    }
    line_end_offset = offset + linelen;
    
    
    semicolon_offset = tvb_find_guint8(tvb, offset, linelen, ':');
    
    value_offset = tvb_skip_wsp(tvb, semicolon_offset, line_end_offset - (semicolon_offset + 1));
    
    tokenlen = line_end_offset - value_offset;
    
    params = (const char *)tvb_get_string_enc(wmem_packet_scope(), tvb, value_offset, tokenlen, ENC_ASCII);
    
    if ((query_str = strchr(params, ':')) != NULL) {
	if (strlen(query_str) > 1) {
	    query_str ++;
	    query_str_len = (int)strlen(query_str);
	    
	    params_len = (int)strlen(params);
	    
	    path_len = params_len - query_str_len;
	    
	    query_offset = value_offset + path_len;
	    
	    query_tree = proto_item_add_subtree(yimp_tree, ett_yimp);
	    
	    proto_tree_add_string(query_tree, hf_yimp_parameter_success, tvb, query_offset, query_str_len, query_str);
	    
	    return (TRUE);
	}
    }
    
    offset += len_tvb;
    return offset;
}


static gint
dissect_yimp_uninstall_enque(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset, void *data _U_)
{
    guint len_tvb = 0;
    proto_item *ti;
    proto_tree *yimp_tree;
    gint value_offset = 0;
    gint line_end_offset = 0, semicolon_offset = 0;
    proto_tree *query_tree;
    int tokenlen = 0;
    int path_len = 0;
    const char *params = 0;
    gchar *query_str = 0;
    int query_str_len = 0, params_len = 0, query_offset = 0;
    gint linelen = 0, next_offset = 0;
    gint procent_offset = 0;
    gint length = 0;
    
    len_tvb = yimp_find_pdu_len(tvb, offset);
    ti = proto_tree_add_protocol_format(tree, proto_yimp, tvb, 0, -1, "Yate's Internal Messages Protocol (%d bytes)",len_tvb);
    yimp_tree = proto_item_add_subtree(ti, ett_yimp);
    
    procent_offset = tvb_find_guint8(tvb, offset, -1, ':');
    length = procent_offset - offset;
    proto_tree_add_item(yimp_tree, hf_yimp_command, tvb, offset, length, ENC_UTF_8|ENC_NA);
    offset = procent_offset + 1;
    
    linelen = tvb_find_line_end(tvb, offset, -1, &next_offset, FALSE);
    if (linelen == 0) {
	
	offset = next_offset;
    }
    line_end_offset = offset + linelen;
    
    semicolon_offset = tvb_find_guint8(tvb, offset, linelen, ':');
    
    value_offset = tvb_skip_wsp(tvb, semicolon_offset, line_end_offset - (semicolon_offset + 1));
    
    tokenlen = line_end_offset - value_offset;
    
    params = (const char *)tvb_get_string_enc(wmem_packet_scope(), tvb, value_offset, tokenlen, ENC_ASCII);
    
    if ((query_str = strchr(params, ':')) != NULL) {
	if (strlen(query_str) > 1) {
	    query_str ++;
	    query_str_len = (int)strlen(query_str);
	    
	    params_len = (int)strlen(params);
	    
	    path_len = params_len - query_str_len;
	    
	    query_offset = value_offset + path_len;
	    
	    query_tree = proto_item_add_subtree(yimp_tree, ett_yimp);
	    
	    proto_tree_add_string(query_tree, hf_yimp_name, tvb, query_offset, query_str_len, query_str);
	    
	    col_append_fstr(pinfo->cinfo, COL_INFO, "Uninstall:%s ", query_str);
	    return (TRUE);
	}
    }
    
    offset += len_tvb;
    return offset;
}

static gint
dissect_yimp_connect(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset, void *data _U_)
{
    guint len_tvb = 0;
    proto_item *ti;
    proto_tree *yimp_tree;
    gint value_offset = 0;
    gint line_end_offset = 0, semicolon_offset = 0;
    proto_tree *query_tree;
    int tokenlen = 0;
    int path_len = 0;
    const char *params = 0;
    gchar *query_str = 0;
    int query_str_len = 0, params_len = 0, query_offset = 0;
    gint linelen = 0, next_offset = 0;
    gint procent_offset = 0;
    gint length = 0;
    
    len_tvb = yimp_find_pdu_len(tvb, offset);
    ti = proto_tree_add_protocol_format(tree, proto_yimp, tvb, 0, -1, "Yate's Internal Messages Protocol (%d bytes)",len_tvb);
    yimp_tree = proto_item_add_subtree(ti, ett_yimp);
    
    procent_offset = tvb_find_guint8(tvb, offset, -1, ':');
    length = procent_offset - offset;
    proto_tree_add_item(yimp_tree, hf_yimp_command, tvb, offset, length, ENC_UTF_8|ENC_NA);
    offset = procent_offset + 1;
    
    linelen = tvb_find_line_end(tvb, offset, -1, &next_offset, FALSE);
    if (linelen == 0) {
	
	offset = next_offset;
    }
    line_end_offset = offset + linelen;
    
    semicolon_offset = tvb_find_guint8(tvb, offset, linelen, ':');
    
    value_offset = tvb_skip_wsp(tvb, semicolon_offset, line_end_offset - (semicolon_offset + 1));
    
    tokenlen = line_end_offset - value_offset;
    
    params = (const char *)tvb_get_string_enc(wmem_packet_scope(), tvb, value_offset, tokenlen, ENC_ASCII);
    
    if ((query_str = strchr(params, ':')) != NULL) {
	if (strlen(query_str) > 1) {
	    query_str ++;
	    query_str_len = (int)strlen(query_str);
	    
	    params_len = (int)strlen(params);
	    
	    path_len = params_len - query_str_len;
	    
	    query_offset = value_offset + path_len;
	    
	    query_tree = proto_item_add_subtree(yimp_tree, ett_yimp);
	    proto_tree_add_string(query_tree, hf_yimp_role, tvb, query_offset, query_str_len, query_str);
	    
	    col_append_fstr(pinfo->cinfo, COL_INFO, "Connect:%s ", query_str);
	    return (TRUE);
	}
    }
    
    offset += len_tvb;
    return offset;
}

static gint
dissect_yimp_unwatch_dispatch(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset, void *data _U_)
{
    guint len_tvb = 0;
    proto_item *ti;
    proto_tree *yimp_tree;
    gint value_offset = 0;
    gint line_end_offset = 0, semicolon_offset = 0;
    proto_tree *query_tree;
    int tokenlen = 0;
    int path_len = 0;
    const char *params = 0;
    gchar *query_str = 0;
    int query_str_len = 0, params_len = 0, query_offset = 0;
    gint linelen = 0, next_offset = 0;
    gint procent_offset = 0;
    gint length = 0;
    
    len_tvb = yimp_find_pdu_len(tvb, offset);
    ti = proto_tree_add_protocol_format(tree, proto_yimp, tvb, 0, -1, "Yate's Internal Messages Protocol (%d bytes)",len_tvb);
    yimp_tree = proto_item_add_subtree(ti, ett_yimp);
    
    procent_offset = tvb_find_guint8(tvb, offset, -1, ':');
    length = procent_offset - offset;
    proto_tree_add_item(yimp_tree, hf_yimp_command, tvb, offset, length, ENC_UTF_8|ENC_NA);
    offset = procent_offset + 1;
    
    linelen = tvb_find_line_end(tvb, offset, -1, &next_offset, FALSE);
    if (linelen == 0) {
	
	offset = next_offset;
    }
    line_end_offset = offset + linelen;
    
    semicolon_offset = tvb_find_guint8(tvb, offset, linelen, ':');
    
    value_offset = tvb_skip_wsp(tvb, semicolon_offset, line_end_offset - (semicolon_offset + 1));
    
    tokenlen = line_end_offset - value_offset;
    
    params = (const char *)tvb_get_string_enc(wmem_packet_scope(), tvb, value_offset, tokenlen, ENC_ASCII);
    
    if ((query_str = strchr(params, ':')) != NULL) {
	if (strlen(query_str) > 1) {
	    query_str ++;
	    query_str_len = (int)strlen(query_str);
	    
	    params_len = (int)strlen(params);
	    
	    path_len = params_len - query_str_len;
	    
	    query_offset = value_offset + path_len;
	    
	    query_tree = proto_item_add_subtree(yimp_tree, ett_yimp);
	    
	    proto_tree_add_string(query_tree, hf_yimp_parameter_watch, tvb, query_offset, query_str_len, query_str);
	    
	    col_add_fstr(pinfo->cinfo, COL_INFO, "Unwatch:%s ", query_str);
	    return (TRUE);
	}
    }
    offset += len_tvb;
    return offset;
}

static gint
dissect_yimp_unwatch_enque(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset, void *data _U_)
{
    gint procent_offset = 0;
    guint len_tvb = 0;
    proto_item *ti;
    proto_tree *yimp_tree;
    gint length = 0;
    gint value_offset = 0;
    gint line_end_offset = 0, semicolon_offset = 0;
    proto_tree *query_tree;
    int tokenlen = 0;
    int path_len = 0;
    const char *params = 0;
    gchar *query_str = 0;
    const char *success_str = 0;
    int query_str_len = 0, params_len = 0, query_offset = 0;
    gint linelen = 0, next_offset = 0;
    
    len_tvb = yimp_find_pdu_len(tvb, offset);
    ti = proto_tree_add_protocol_format(tree, proto_yimp, tvb, 0, -1, "Yate's Internal Messages Protocol (%d bytes)",len_tvb);
    yimp_tree = proto_item_add_subtree(ti, ett_yimp);
    
    procent_offset = tvb_find_guint8(tvb, offset, -1, ':');
    length = procent_offset - offset;
    proto_tree_add_item(yimp_tree, hf_yimp_command, tvb, offset, length, ENC_UTF_8|ENC_NA);
    offset = procent_offset + 1;
    
    procent_offset = tvb_find_guint8(tvb, offset, -1, ':');
    length = procent_offset - offset;
    proto_tree_add_item(yimp_tree, hf_yimp_parameter_watch, tvb, offset, length, ENC_UTF_8|ENC_NA);
    success_str = (const char *)tvb_get_string_enc(wmem_packet_scope(), tvb, offset, length, ENC_ASCII);
    col_add_fstr(pinfo->cinfo, COL_INFO, "Unwatch:%s", success_str);
    
    linelen = tvb_find_line_end(tvb, offset, -1, &next_offset, FALSE);
    if (linelen == 0) {
	
	offset = next_offset;
    }
    line_end_offset = offset + linelen;
    
    semicolon_offset = tvb_find_guint8(tvb, offset, linelen, ':');
    
    value_offset = tvb_skip_wsp(tvb, semicolon_offset, line_end_offset - (semicolon_offset + 1));
    
    tokenlen = line_end_offset - value_offset;
    
    params = (const char *)tvb_get_string_enc(wmem_packet_scope(), tvb, value_offset, tokenlen, ENC_ASCII);
    
    if ((query_str = strchr(params, ':')) != NULL) {
	if (strlen(query_str) > 1) {
	    query_str ++;
	    query_str_len = (int)strlen(query_str);
	    
	    params_len = (int)strlen(params);
	    
	    path_len = params_len - query_str_len;
	    
	    query_offset = value_offset + path_len;
	    
	    query_tree = proto_item_add_subtree(yimp_tree, ett_yimp);
	    
	    proto_tree_add_string(query_tree, hf_yimp_parameter_success, tvb, query_offset, query_str_len, query_str);
	    
	    return (TRUE);
	}
    }
    
    offset += len_tvb;
    return offset;
}

static gint
dissect_setlocal_dispatch(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset, void *data _U_)
{
    
    gint procent_offset = 0;
    guint len_tvb = 0;
    proto_item *ti;
    proto_tree *yimp_tree;
    gint length = 0;
    gint value_offset = 0;
    gint line_end_offset = 0, semicolon_offset = 0;
    proto_tree *query_tree;
    int tokenlen = 0;
    int path_len = 0;
    const char *params = 0;
    gchar *query_str = 0;
    const char *success_str = 0;
    int query_str_len = 0, params_len = 0, query_offset = 0;
    gint linelen = 0, next_offset = 0;
    
    len_tvb = yimp_find_pdu_len(tvb, offset);
    ti = proto_tree_add_protocol_format(tree, proto_yimp, tvb, 0, -1, "Yate's Internal Messages Protocol (%d bytes)",len_tvb);
    yimp_tree = proto_item_add_subtree(ti, ett_yimp);
    linelen = tvb_find_line_end(tvb, offset, -1, &next_offset, FALSE);
    if (linelen == 0) {
	
	offset = next_offset;
    }
    line_end_offset = offset + linelen;
    
    procent_offset = tvb_find_guint8(tvb, offset, -1, ':');
    length = procent_offset - offset;
    proto_tree_add_item(yimp_tree, hf_yimp_command, tvb, offset, length, ENC_UTF_8|ENC_NA);
    offset = procent_offset + 1;
    
    procent_offset = tvb_find_guint8(tvb, offset, -1, ':');
    length = procent_offset - offset;
    proto_tree_add_item(yimp_tree, hf_yimp_name, tvb, offset, length, ENC_UTF_8|ENC_NA);
    success_str = (const char *)tvb_get_string_enc(wmem_packet_scope(), tvb, offset, length, ENC_ASCII);
    col_append_fstr(pinfo->cinfo, COL_INFO, "Setlocal:%s ", success_str);
    offset = procent_offset + 1;
    
    procent_offset = tvb_find_guint8(tvb, offset, -1, ':');
    length = procent_offset - offset;
    proto_tree_add_item(yimp_tree, hf_yimp_parameter_value, tvb, offset, length, ENC_UTF_8|ENC_NA);
    
    linelen = tvb_find_line_end(tvb, offset, -1, &next_offset, FALSE);
    if (linelen == 0) {
	
	offset = next_offset;
    }
    line_end_offset = offset + linelen;
    
    semicolon_offset = tvb_find_guint8(tvb, offset, linelen, ':');
    
    value_offset = tvb_skip_wsp(tvb, semicolon_offset, line_end_offset - (semicolon_offset + 1));
    
    tokenlen = line_end_offset - value_offset;
    
    params = (const char *)tvb_get_string_enc(wmem_packet_scope(), tvb, value_offset, tokenlen, ENC_ASCII);
    
    if ((query_str = strchr(params, ':')) != NULL) {
	if (strlen(query_str) > 1) {
	    query_str ++;
	    query_str_len = (int)strlen(query_str);
	    
	    params_len = (int)strlen(params);
	    
	    path_len = params_len - query_str_len;
	    
	    query_offset = value_offset + path_len;
	    
	    query_tree = proto_item_add_subtree(yimp_tree, ett_yimp);
	    
	    proto_tree_add_string(query_tree, hf_yimp_parameter_success, tvb, query_offset, query_str_len, query_str);
	    
	}
    }
    
    offset += len_tvb;
    return offset;
}


static int
data_length(tvbuff_t *tvb, int offset)
{
    int skip_offset = 0;
    int length = 0;
    const char* col_length = 0;
    const char *line_length = 0;
    int result = 0;
    int col_size = 0, line_size = 0;
    int i = 0;
    guint32 size = 0, size_bytes = 0, shift = 0;
    guint8 tmp = 0;
    guint16 element_length = 0;
    
    skip_offset = tvb_find_guint8(tvb, offset, -1, ':');
    
    offset = skip_offset + 1;
    
    skip_offset = tvb_find_guint8(tvb, offset, -1, ':');
    length = skip_offset - offset;
    col_length = (const char *)tvb_get_string_enc(wmem_packet_scope(), tvb, offset, length, ENC_ASCII);
    offset = skip_offset + 1;
    
    skip_offset = tvb_find_guint8(tvb, offset, -1, 0x0d);
    length = skip_offset - offset;
    line_length = (const char *)tvb_get_string_enc(wmem_packet_scope(), tvb, offset, length, ENC_ASCII);
    offset = skip_offset + 1;
    
    skip_offset = tvb_find_guint8(tvb, offset, -1, 0x0a);
    offset = skip_offset + 1;
    
    col_size = atoi(col_length);
    line_size = atoi(line_length);
    result  = col_size * line_size;
    
    for(i = 0; i < result; i++){
	
	size = 0;
	size_bytes = 0;
	shift = 0;
	do {
	    tmp = tvb_get_guint8(tvb, offset + size_bytes);
	    size_bytes += 1;
	    
	    size |= (size << shift) | (tmp & 0x7f);
	    shift += 7;
	} while ((tmp & 0x80) && (shift < 32));

	element_length  = (size - 1)/2;
	
	if(size == 0)
	    element_length = 0;
	
	
	if (size <= 0x7F)
	    offset += 1 + element_length;
	else if (size <= 0x7FFF)
	    offset += 2 + element_length;
	else if (size <= 0x7FFFFFFF)
	    offset += 4 + element_length;

    }

    return offset;
}

const char *str_slice(const char *str, int slice_from, int slice_to)
{
    char *buffer = 0;
    size_t buffer_len = 0;
    int str_len = 0;
    
    if(str[0] == '\0')
	return NULL;
    
    if(slice_to < 0 && slice_from < slice_to)
    {
	str_len = strlen(str);
	
	if(abs(slice_from) > str_len - 1)
	    slice_from = (-1) * str_len;
	
	buffer_len = slice_to - slice_from;
	str += (str_len + slice_from);
    }
    else if(slice_from >= 0 && slice_to > slice_from)
    {
	str_len = strlen(str);
	
	if(slice_from > str_len - 1)
	    return NULL;
	
	buffer_len = slice_to - slice_from;
	str += slice_from;
    }
    else
	return NULL;
    
    buffer = (char*)calloc(buffer_len, sizeof(char));
    strncpy(buffer, str, buffer_len);
    return buffer;
}

int lenUtf8(const char* value, guint32 maxChar)
{
    
    int count = 0;
    unsigned int more = 0;
    guint32 min = 0;
    guint32 val = 0;
    unsigned char c;
    
    if(!value)
	return 0;
    if(maxChar < 128)
	maxChar = 0x10ffff;
    
    while ((c = (unsigned char) *value++))
    {
	if (more)
	{
	    if ((c & 0xc0) != 0x80)
		return -1;
	    val = (val << 6) | (c & 0x3f);
	    if(!--more)
	    {
		if (val > maxChar)
		    return -1;
		if (val < min)
		    return -1;
	    }
	    continue;
	}
	count++;
	
	if (c < 0x80)
	    ;
	else if (c < 0xc0)
	    return -1;
	else if (c < 0xe0)
	{
	    min = 0x80;
	    val = c & 0x1f;
	    more = 1;
	}
	else if (c < 0xf0)
	{
	    min = 0x800;
	    val = c & 0x0f;
	    more = 2;
	}
	else if (c < 0xf8)
	{
	    min = 0x10000;
	    val = c & 0x07;
	    more = 3;
	}
	else if (c < 0xfc)
	{
	    min = 0x200000;
	    val = c & 0x03;
	    more = 4;
	}
	else if (c < 0xfe)
	{
	    min = 0x4000000;
	    val = c & 0x01;
	    more = 5;
	}
	else
	    return -1;
    }
    if (more)
	return -1;
    return count;
}


const char* string_padding(const char string[], int len)
{
    
    const char *pad = 0;
    int i = 0;
    i = g_snprintf(NULL,0,"%s",string);
    pad = (const char*)malloc(len+i+1);
    if (len > 0) {
	g_sprintf((char*)pad,"%s%*s", string , len, " ");
    }
    else if (len == 0) {
	pad = string;
    }
    else
	return NULL;
    
    return pad;
    
}


const char *concatenate(size_t size, const char **array, int start, int pas, const char *sep)
{
    size_t jlen = 0;
    size_t len[size];
    size_t i, total_size = (size - 1) * (jlen=strlen(sep)) + 1;
    char *result, *p;
    for (i = 0; i < size; i++)
    {
	total_size += (len[i]=strlen(array[i]));
    }
    p = result = (char *)malloc(total_size);
    for (i=start;i<size;i+= pas){
	memcpy(p, array[i], len[i]);
	p += len[i];
	if(i<size-1){
	    memcpy(p, sep, jlen);
	    p += jlen;
	}
    }
    *p = '\0';
    return result;
}

static int
dissect_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, void *data _U_)
{
    int start_offset = 0;
    gint tokenlen = 0;
    guint16 len_tvb = 0;
    proto_item *ti;
    proto_tree *yimp_tree;
    gint length = 0;
    proto_tree *tlv_tree, *query_tree;
    guint8 element_length = 0;
    const char* col_length = 0;
    const char *line_length = 0;
    int result = 0;
    int query_str_len = 0;
    guint col_size, line_size;
    int skip_offset = 0;
    guint32 size, size_bytes, shift;
    guint8 tmp = 0;
    const char *query_str = 0;
    const char *params = 0;
    const char *array[20000] = { 0 };
    const char *buf[25000] = { 0 };
    int maxlen = 0;
    int len[1000] = {0};
    const char *con;
    int i = 0;
    int v = 0;
    int n;
    int j;
    unsigned int x;
    
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "YIMP");
    
    len_tvb = data_length(tvb, offset);
    
    ti = proto_tree_add_protocol_format(tree, proto_yimp, tvb, 0, -1, "Yate's Internal Messages Protocol (%d bytes)",len_tvb);
    yimp_tree = proto_item_add_subtree(ti, ett_yimp);
    
    skip_offset = tvb_find_guint8(tvb, offset, -1, ':');
    length = skip_offset - offset;
    proto_tree_add_item(yimp_tree, hf_yimp_command, tvb, offset, length, ENC_UTF_8|ENC_NA);
    offset = skip_offset + 1;
    
    skip_offset = tvb_find_guint8(tvb, offset, -1, ':');
    length = skip_offset - offset;
    col_length = (const char *)tvb_get_string_enc(wmem_packet_scope(), tvb, offset, length, ENC_ASCII);
    proto_tree_add_item(yimp_tree, hf_yimp_data_columns, tvb, offset, length, ENC_UTF_8|ENC_NA);
    offset = skip_offset + 1;
    
    skip_offset = tvb_find_guint8(tvb, offset, -1, 0x0d);
    length = skip_offset - offset;
    line_length = (const char *)tvb_get_string_enc(wmem_packet_scope(), tvb, offset, length, ENC_ASCII);
    proto_tree_add_item(yimp_tree, hf_yimp_data_lines, tvb, offset, length, ENC_UTF_8|ENC_NA);
    offset = skip_offset + 1;
    
    
    skip_offset = tvb_find_guint8(tvb, offset, -1, 0x0a);
    offset = skip_offset + 1;
    
    col_size = atoi(col_length);
    line_size = atoi(line_length);
    result = col_size * line_size;
    
    col_append_fstr(pinfo->cinfo, COL_INFO, "Data: %d Lines x %d Columns ", line_size, col_size);
    
    
    for (n = 0; n < result; n++)    {
	
	size = 0;
	size_bytes = 0;
	shift = 0;
	do {
	    tmp = tvb_get_guint8(tvb, offset + size_bytes);
	    size_bytes += 1;
	    
	    size |= (size << shift) | (tmp & 0x7f);
	    shift += 7;
	} while ((tmp & 0x80) && (shift < 32));
	
	
	offset += size_bytes;
	
	element_length  = (size - 1)/2;
	
	if(size == 0)
	    element_length = 0;
	
	
	query_str = (const char *)tvb_get_string_enc(wmem_packet_scope(), tvb, offset, element_length, ENC_UTF_8);
	
	
	buf[n] = query_str;
	
	offset += element_length;
	
	if(offset == len_tvb)
	    break;
	
    }
    
    
    for(v = 0; v < col_size; v++) {
	maxlen = len[i];
	
	for( i = 0; i < line_size ; i++) { 
	    
	    len[i] = lenUtf8(buf[v*line_size + i], 0x10ffff);
	    
	    if(len[i] > maxlen)
	    {
		maxlen = len[i];
	    }
	}
	
	for(j = 0; j < line_size ; j++) { 
	    
	    len[j] = lenUtf8(buf[v*line_size + j], 0x10ffff);
	    
	    if(len[j] < maxlen)
	    {
		buf[v*line_size + j] = string_padding(buf[v*line_size + j], maxlen - len[j]);
		
	    }
	    array[v*line_size + j] = buf[v*line_size + j];
	}
	
	
    }

    tokenlen = len_tvb - offset;

    params = (const char *)tvb_get_string_enc(wmem_packet_scope(), tvb, offset, tokenlen, ENC_UTF_8);
    
    tlv_tree = proto_tree_add_string(yimp_tree, hf_yimp_message, tvb, offset + 1, tokenlen, params);
    
    proto_item_set_text(tlv_tree, "RECORDS");
    
    query_tree = proto_item_add_subtree(tlv_tree, ett_yimp);
    
    for (x = 0; x < line_size; x+=1)
    {
	con  = concatenate(result, array, x, line_size, " ");

	query_str_len = (int)strlen(con);

	proto_tree_add_string(query_tree, hf_yimp_line, tvb, start_offset, query_str_len, con);
	
    }
    
    offset += len_tvb;
    return offset;
    
}

typedef enum
{
    Data,
    Message1,
    Message2,
    Version1,
    Version2,
    Watch1,
    Watch2,
    Auth1,
    Auth2,
    Install1,
    Install2,
    Setlocal1,
    Setlocal2,
    Output1,
    Quit1,
    Quit2,
    Status1,
    Status2,
    Ping1,
    Ping2,
    Connect1,
    Uninstall1,
    Uninstall2,
    Unwatch1,
    Unwatch2
    
}COMMANDS;

static const struct {
    COMMANDS cmd;
    const char *str;
}conversion [] = {
    {Data, "%%<data"},
    {Message1, "%%<message"},
    {Message2, "%%>message"},
    {Version1, "%%>version"},
    {Version2, "%%<version"},
    {Watch1, "%%>watch"},
    {Watch2, "%%<watch"},
    {Auth1, "%%>auth"},
    {Auth2, "%%<auth"},
    {Install1, "%%<install"},
    {Install2, "%%>install"},
    {Setlocal1, "%%>setlocal"},
    {Setlocal2, "%%<setlocal"},
    {Output1, "%%>output"},
    {Quit1, "%%>quit"},
    {Quit2, "%%<quit"},
    {Status1, "%%>status"},
    {Status2, "%%<status"},
    {Ping1, "%%<ping"},
    {Ping2, "%%>ping"},
    {Connect1, "%%>connect"},
    {Uninstall1, "%%>uninstall"},
    {Uninstall2, "%%<uninstall"},
    {Unwatch1, "%%>unwatch"},
    {Unwatch2, "%%<unwatch"}
};

COMMANDS str2enum(const char *str)
{
    unsigned int j;
    for (j = 0;  j < sizeof (conversion) / sizeof (conversion[0]);  ++j)
    {
	if (!strncmp (str, conversion[j].str, strlen(conversion[j].str)))
	{
	    return conversion[j].cmd;
	}
    }
    return conversion[j].cmd;
}


static int
dissect_commands(tvbuff_t *tvb,packet_info *pinfo, proto_tree *tree, int offset, void *data _U_)
{
    
    int end_offset = 0;
    int length = 0;
    int len = 0;
    const char *query_str = 0;
    
    COMMANDS cmd;
    
    length = tvb_reported_length_remaining(tvb, offset);
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "YIMP");
    
    offset = 0;
    
    while(length > 0){
	
	len = tvb_reported_length(tvb);
	end_offset = yimp_find_pdu_len(tvb, offset);
	if(end_offset == -1)
	    return offset;
	
	query_str = (const char *)tvb_get_string_enc(wmem_packet_scope(), tvb, offset, end_offset, ENC_ASCII);
	cmd = str2enum(query_str);
	
	switch (cmd)
	{
	    case Version1:
		dissect_version(tvb, pinfo, tree, offset, data);
		break;
	    case Version2:
		dissect_version(tvb, pinfo, tree, offset, data);
		break;
	    case Auth1:
		dissect_yimp_auth(tvb, pinfo, tree, offset, data);
		break;
	    case Auth2:
		dissect_yimp_auth(tvb, pinfo, tree, offset, data);
		break;
	    case Message1:
		dissect_yimp_tcp_dispatch(tvb, pinfo, tree, offset);
		break;
	    case Message2:
		dissect_yimp_tcp_enque(tvb, pinfo, tree, offset);
		break;
	    case Watch1:
		dissect_yimp_watch_enque(tvb, pinfo, tree, offset, data);
		break;
	    case Watch2:
		dissect_yimp_watch_dispatch(tvb, pinfo, tree, offset);
		break;
	    case Install1:
		dissect_install_dispatch(tvb, pinfo, tree, offset, data);
		break;
	    case Install2:
		dissect_install_enque(tvb, pinfo, tree, offset, data);
		break;
	    case Setlocal1:
		dissect_setlocal_enque(tvb, pinfo, tree, offset, data);
		break;
	    case Setlocal2:
		dissect_setlocal_dispatch(tvb, pinfo, tree, offset, data);
		break;
	    case Output1:
		dissect_output(tvb, pinfo, tree, offset);
		break;
	    case Quit1:
		dissect_yimp_quit(tvb, pinfo, tree, offset);
		break;
	    case Quit2:
		dissect_yimp_quit(tvb, pinfo, tree, offset);
		break;
	    case Status1:
		dissect_yimp_status(tvb, pinfo, tree, offset, data);
		break;
	    case Status2:
		dissect_yimp_status(tvb, pinfo, tree, offset, data);
		break;
	    case Ping1:
		dissect_yimp_ping(tvb, pinfo, tree, offset, data);
		break;
	    case Ping2:
		dissect_yimp_ping(tvb, pinfo, tree, offset, data);
		break;
	    case Connect1:
		dissect_yimp_connect(tvb, pinfo, tree, offset, data);
		break;
	    case Uninstall1:
		dissect_yimp_uninstall_enque(tvb, pinfo, tree, offset, data);
		break;
	    case Uninstall2:
		dissect_yimp_uninstall_dispatch(tvb, pinfo, tree, offset, data);
		break;
	    case Unwatch1:
		dissect_yimp_unwatch_dispatch(tvb, pinfo, tree, offset, data);
		break;
	    case Unwatch2:
		dissect_yimp_unwatch_enque(tvb, pinfo, tree, offset, data);
		break;
	    case Data:
		dissect_data(tvb, pinfo, tree, offset, data);
		offset += data_length(tvb, offset);
		offset -= end_offset;
		break;
	    default:
		proto_tree_add_item(tree, hf_yimp_tlv_dataremain, tvb, offset, end_offset, ENC_ASCII);
		break;
	}
	
	offset += end_offset ;
	len -= offset;
    }
    
    return tvb_reported_length(tvb);
}

static int
dissect_yimp_tcp_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    int offset = 0;
    gint linelen = 0, length = 0;
    gint procent_offset = 0;
    
    if ((tvb_captured_length(tvb) < 2) ||
	(tvb_strncaseeql(tvb, 0, "%%", 2) != 0) )
	return FALSE;
    
    col_clear(pinfo->cinfo, COL_PROTOCOL);
    col_clear(pinfo->cinfo, COL_INFO);
    linelen = yimp_find_pdu_len(tvb, offset);
    
    
    if (linelen == -1)
    {
	
	if (pinfo->can_desegment)
	{
	    pinfo->desegment_offset = offset ;
	    pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
	    return TRUE;
	}
    }
    
    
    if ((tvb_strncaseeql(tvb, 0, "%%<data", 7) == 0)  && tvb_reported_length_remaining(tvb, offset) > 2000)
    {
	procent_offset = linelen + 1;
	length = yimp_find_pdu_len(tvb, procent_offset);

	if (pinfo -> can_desegment)
	{
	    if(length == -1)
	    {
		pinfo->desegment_offset = offset;
		pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
		return tvb_captured_length(tvb);
	    }
	    
	}
	
    }
    
    dissect_commands(tvb, pinfo, tree, offset, data);
    
    return tvb_captured_length(tvb);
    
}



static int
dissect_yimp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    conversation_t *conversation;
    guint len_tvb = 0;
    proto_item *ti;
    proto_tree *yimp_tree;
    guint32 offset = 0;
    proto_item *tlv_tree;
    proto_tree *query_tree;
    gint procent_offset = 0;
    gint semicolon_offset = 0;
    gint line_end_offset = 0, length = 0;
    gint next_offset = 0, linelen = 0;
    gint value_offset = 0;
    int tokenlen = 0;
    int path_len = 0;
    const char *params = 0;
    gchar *query_str = 0, *parameter_str = 0, *retvalue_str = 0;
    const char *name_str = 0;
    int query_str_len = 0, params_len = 0, query_offset = 0;
    int parameter_str_len = 0;
    
    conversation = find_or_create_conversation(pinfo);
    conversation_set_dissector(conversation, yimp_handle);
    
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "YIMP");
    col_add_fstr(pinfo->cinfo, COL_INFO, "Yate's Internal Messages Protocol");
    
    len_tvb = tvb_reported_length(tvb);
    ti = proto_tree_add_protocol_format(tree, proto_yimp, tvb, 0, -1, "Yate's Internal Messages Protocol (%d bytes)", len_tvb);
    
    yimp_tree = proto_item_add_subtree(ti, ett_yimp);
    
    offset += 8;
    while(offset < len_tvb)
    {
	offset = dissect_tlvs(tvb, yimp_tree, offset);
	
	if(tvb_strncaseeql(tvb, offset, "%%>message", 10 ) == 0)
	{
	    
	    procent_offset = tvb_find_guint8(tvb, offset, -1, ':');
	    length = procent_offset - offset;
	    proto_tree_add_item(yimp_tree, hf_yimp_command, tvb, offset, length, ENC_UTF_8|ENC_NA);
	    offset = procent_offset + 1;
	    
	    procent_offset = tvb_find_guint8(tvb, offset, -1, ':');
	    length = procent_offset - offset;
	    proto_tree_add_item(yimp_tree, hf_yimp_id, tvb, offset, length, ENC_UTF_8|ENC_NA);
	    offset = procent_offset + 1;
	    
	    procent_offset = tvb_find_guint8(tvb, offset, -1, ':');
	    length = procent_offset - offset;
	    proto_tree_add_item(yimp_tree, hf_yimp_time, tvb, offset, length, ENC_UTF_8|ENC_NA);
	    offset = procent_offset + 1;
	    
	    procent_offset = tvb_find_guint8(tvb, offset, -1, ':');
	    length = procent_offset - offset;
	    proto_tree_add_item(yimp_tree, hf_yimp_name, tvb, offset, length, ENC_UTF_8|ENC_NA);
	    name_str = (const char *)tvb_get_string_enc(wmem_packet_scope(), tvb, offset, length, ENC_ASCII);
	    col_add_fstr(pinfo->cinfo, COL_INFO, "Message: %s", name_str);
	    offset = procent_offset + 1;
	    if (offset == len_tvb)
		break;
	    
	    procent_offset = tvb_find_guint8(tvb, offset, -1, ':');
	    length = procent_offset - offset;
	    retvalue_str = (gchar *)tvb_get_string_enc(wmem_packet_scope(), tvb, offset, length, ENC_ASCII);
	    replace(retvalue_str, "%J", " ");
	    proto_tree_add_string(yimp_tree, hf_yimp_retvalue, tvb, offset,length, retvalue_str);
	    offset = procent_offset;

	    linelen = tvb_find_line_end(tvb, offset, -1, &next_offset, FALSE);

	    if (linelen == 0) {
		
		offset = next_offset;
		
		break;
	    }
	    line_end_offset = offset + linelen;
	    
	    semicolon_offset = tvb_find_guint8(tvb, offset, linelen, ':');
	    
	    value_offset = tvb_skip_wsp(tvb, semicolon_offset, line_end_offset - (semicolon_offset + 1));
	    
	    tokenlen = line_end_offset - value_offset;
	    
	    params = (const char *)tvb_get_string_enc(wmem_packet_scope(), tvb, value_offset, tokenlen, ENC_UTF_8);
	    
	    tlv_tree = proto_tree_add_string(yimp_tree, hf_yimp_message, tvb, value_offset, tokenlen, params);
	    proto_item_set_text(tlv_tree, "PARAMETERS");
	    if ((query_str = strchr(params, ':')) != NULL) {
		if (strlen(query_str) > 1) {
		    query_str ++;
		    query_str_len = (int)strlen(query_str);
		    
		    params_len = (int)strlen(params);
		    
		    path_len = params_len - query_str_len;
		    
		    query_offset = value_offset + path_len;
		    
		    query_tree = proto_item_add_subtree(tlv_tree, ett_yimp);
		    
		    for(parameter_str = strtok(query_str, ":"); parameter_str; parameter_str = strtok(NULL, ":"))
		    {
			parameter_str_len = (int)strlen(parameter_str);
			replace(parameter_str, "%z", ":");
			proto_tree_add_string(query_tree, hf_yimp_parameter, tvb, query_offset, parameter_str_len, parameter_str);
			query_offset += parameter_str_len + 1;
		    }
		    
		    
		}
		
	    }
	    
	    return tvb_reported_length(tvb);
	    
	}
	
	else if (tvb_strncaseeql(tvb, offset,"%%<message" , 10) == 0)
	{
	    procent_offset = tvb_find_guint8(tvb, offset, -1, ':');
	    length = procent_offset - offset;
	    proto_tree_add_item(yimp_tree, hf_yimp_command, tvb, offset, length, ENC_UTF_8|ENC_NA);
	    offset = procent_offset + 1;
	    
	    procent_offset = tvb_find_guint8(tvb, offset, -1, ':');
	    length = procent_offset - offset;
	    proto_tree_add_item(yimp_tree, hf_yimp_id, tvb, offset, length, ENC_UTF_8|ENC_NA);
	    offset = procent_offset + 1;
	    
	    procent_offset = tvb_find_guint8(tvb, offset, -1, ':');
	    length = procent_offset - offset;
	    proto_tree_add_item(yimp_tree, hf_yimp_processed, tvb, offset, length, ENC_UTF_8|ENC_NA);
	    offset = procent_offset + 1;
	    
	    procent_offset = tvb_find_guint8(tvb, offset, -1, ':');
	    length = procent_offset - offset;
	    proto_tree_add_item(yimp_tree, hf_yimp_name, tvb, offset, length, ENC_UTF_8|ENC_NA);
	    name_str = (const char *)tvb_get_string_enc(wmem_packet_scope(), tvb, offset, length, ENC_ASCII);
	    col_add_fstr(pinfo->cinfo, COL_INFO, "Message: %s", name_str);
	    offset = procent_offset + 1;
	    if (offset == len_tvb)
		break;
	    
	    procent_offset = tvb_find_guint8(tvb, offset, -1, ':');
	    length = procent_offset - offset;
	    retvalue_str = (gchar *)tvb_get_string_enc(wmem_packet_scope(), tvb, offset, length, ENC_ASCII);
	    replace(retvalue_str, "%J", " ");
	    proto_tree_add_string(yimp_tree, hf_yimp_retvalue, tvb, offset,length, retvalue_str);
	    offset = procent_offset;
	    	    
	    linelen = tvb_find_line_end(tvb, offset, -1, &next_offset, FALSE);
	    if (linelen == 0) {
		
		offset = next_offset;
		break;
	    }
	    line_end_offset = offset + linelen;	    
	    
	    semicolon_offset = tvb_find_guint8(tvb, offset, linelen, ':');

	    value_offset = tvb_skip_wsp(tvb, semicolon_offset, line_end_offset - (semicolon_offset + 1));

	    tokenlen = line_end_offset - value_offset;

	    params = (const char *)tvb_get_string_enc(wmem_packet_scope(), tvb, value_offset, tokenlen, ENC_UTF_8);

	    tlv_tree = proto_tree_add_string(yimp_tree, hf_yimp_message, tvb, value_offset, tokenlen, params);	
	    proto_item_set_text(tlv_tree, "PARAMETERS");
	    if ((query_str = strchr(params, ':')) != NULL) {
		if (strlen(query_str) > 1) {
		    query_str ++;
		    query_str_len = (int)strlen(query_str);
		    params_len = (int)strlen(params);
		    
		    path_len = params_len - query_str_len;
		    
		    query_offset = value_offset + path_len;
		    
		    query_tree = proto_item_add_subtree(tlv_tree, ett_yimp);
		    
		    for(parameter_str = strtok(query_str, ":"); parameter_str; parameter_str = strtok(NULL, ":"))
		    {
			parameter_str_len = (int)strlen(parameter_str);
			replace(parameter_str, "%z", ":");
			proto_tree_add_string(query_tree, hf_yimp_parameter, tvb, query_offset, parameter_str_len, parameter_str);
			query_offset += parameter_str_len + 1;
		    }
		    
		    
		}
		
	    }
	    return tvb_reported_length(tvb);
	}
    }
    
    return tvb_reported_length(tvb);
}

static gboolean
dissect_yimp_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    if( (tvb_captured_length(tvb) < 8) ||
	(tvb_strncaseeql(tvb, 0, "yate-msg", 8) != 0) ) {
	return FALSE;
	}
	
	dissect_yimp(tvb, pinfo, tree, data);
    return (TRUE);
    
}


void
proto_register_yimp( void )
{
    module_t *yimp_module;
    expert_module_t *expert_yimp;
    
    static hf_register_info hf[] = {
	{ &hf_yimp_signature,
	    { "Signature", "yimp.signature",
		FT_STRING, BASE_NONE, NULL, 0x00,
		"Dissector for Yate's internal messages",HFILL }
	},
	
	{ &hf_yimp_tlv_type,
	    { "TlvType","yimp.tlv.type",
		FT_UINT8, BASE_HEX | BASE_EXT_STRING, NULL,
		0x0, NULL, HFILL }
		
	},
	
	{ &hf_yimp_tlv_length,
	    { "TlvLength","yimp.tlv.length",
		FT_UINT8, BASE_HEX, NULL,
		0x0, NULL, HFILL }
		
	},
	
	{ &hf_yimp_tlv_dataremain,
	    { "Garbage","yimp.tlv.data",
		FT_STRING, BASE_NONE, NULL,
		0x0, NULL, HFILL }
		
	},
	
	{ &hf_yimp_output,
	    { "Output","yimp.tlv.data",
		FT_STRING, BASE_NONE, NULL,
		0x0, NULL, HFILL }
		
	},
	
	{ &hf_yimp_line,
	    { "R","yimp.r",
		FT_STRING, BASE_NONE, NULL,
		0x0, NULL, HFILL }
		
	},
	
	{ &hf_yimp_element,
	    { "Element","yimp.tlv.data",
		FT_STRING, BASE_NONE, NULL,
		0x0, NULL, HFILL }
		
	},
	
	{ &hf_yimp_tlv_result,
	    { "Direction", "yimp.result",
		FT_UINT8, BASE_DEC, VALS(yimp_result), 0x0,
		"Type of the encoded message", HFILL }
	},
	
	{ &hf_yimp_tlv_broadcast,
	    { "Broadcast", "yimp.broadcast",
		FT_UINT8, BASE_DEC, VALS(yimp_broadcast), 0x0,
		"Broadcast tag", HFILL }
	},
	
	{ &hf_yimp_tlv_threadpointer,
	    { "ThreadPointer", "yimp.thread_pointer",
		FT_BYTES, BASE_NONE, NULL, 0x0,
		"Pointer to the current thread", HFILL }
	},
	
	{ &hf_yimp_tlv_data,
	    { "DataPointer", "yimp.data_pointer",
		FT_BYTES, BASE_NONE, NULL, 0x0,
		"Pointer to data", HFILL }
	},
	
	{ &hf_yimp_tlv_threadname,
	    { "ThreadName", "yimp.thread_name",
		FT_STRING, BASE_NONE, NULL, 0x00,
		"Name of the current thread", HFILL }
	},
	
	{ &hf_yimp_tlv_final,
	    {"FinalTag", "yimp.final_tag",
		FT_UINT8, BASE_HEX, NULL, 0x0,
		"Final tag", HFILL }
	},
	
	{ &hf_yimp_messagename,
	    { "Message Name", "yimp.message_name",
		FT_STRING, BASE_NONE, NULL, 0x00,
		"Name of the current message", HFILL }
	},
	
	{ &hf_yimp_parameter_data,
	    { "Data", "yimp.data",
		FT_STRING, BASE_NONE, NULL, 0x00,
		"Data", HFILL }
	},
	
	{ &hf_yimp_message,
	    { "Message",  "yimp.message",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"Message", HFILL}
	},
	
	{ &hf_yimp_tlvs,
	    { "TLVS",  "yimp.tlvs",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"TLVS", HFILL}
	},
	
	{ &hf_yimp_id,
	    { "Id",  "yimp.id",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"Obscure unique message ID string generated by Yate", HFILL},
	},
	
	{ &hf_yimp_install_priority,
	    { "Priority",  "yimp.priority",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"Priority in chain, use default (100) if missing", HFILL},
	},
	
	
	{ &hf_yimp_time,
	    { "Time",  "yimp.time",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"Time (in seconds) the message was initially created", HFILL},
	},
	
	{ &hf_yimp_timestamp,
	    { "Timestamp",  "yimp.timestamp",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"Time (in seconds) the message was initially created", HFILL},
	},
	
	{ &hf_yimp_data_columns,
	    { "Columns",  "yimp.columns",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"Columns", HFILL},
	},
	
	{ &hf_yimp_data_lines,
	    { "Lines",  "yimp.lines",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"Lines", HFILL},
	},
	
	
	{ &hf_yimp_hash,
	    { "Hash",  "yimp.hash",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"Hash", HFILL},
	},
	
	{ &hf_yimp_parameter_watch,
	    { "Name",  "yimp.name",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"Name of the messages for that a watcher should be installed", HFILL},
	},
	
	{ &hf_yimp_role,
	    { "Role",  "yimp.role",
		FT_STRING, BASE_NONE, NULL, 0x0,
		NULL, HFILL},
	},
	
	{ &hf_yimp_name,
	    { "Name",  "yimp.name",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"Name of the message", HFILL},
	},
	
	{ &hf_yimp_version,
	    { "Version",  "yimp.version",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"Version", HFILL},
	},
	
	{ &hf_yimp_status,
	    { "Status",  "yimp.status",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"Status", HFILL},
	},
	
	{ &hf_yimp_parameter_success,
	    { "Success",  "yimp.success",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"Boolean success of operation", HFILL},
	},
	
	{ &hf_yimp_processed,
	    { "Processed",  "yimp.processed",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"Boolean indication if the message has been processed or it should be passed to the next handler", HFILL},
	},
	
	{ &hf_yimp_parameter_value,
	    { "Value",  "yimp.value",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"New value to set in the local module instance, empty to just query", HFILL},
	},
	
	{ &hf_yimp_retvalue,
	    { "retvalue",  "yimp.retvalue",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"retvalue", HFILL},
	},
	
	{ &hf_yimp_ping,
	    { "Ping",  "yimp.ping",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"Ping", HFILL},
	},
	
	{ &hf_yimp_nodename,
	    { "Nodename",  "yimp.nodename",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"Nodname of the message", HFILL},
	},
	
	{ &hf_yimp_handlers,
	    { "Handlers",  "yimp.handlers",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"Handlers of the message", HFILL},
	},
	
	{ &hf_yimp_fulltext,
	    { "Full text", "yimp.fulltext",
		FT_STRING, BASE_NONE, NULL, 0x00,
		"Full text", HFILL }
	},
	
	{ &hf_yimp_test,
	    { "Test", "yimp.test",
		FT_STRING, BASE_NONE, NULL, 0x00,
		"Test", HFILL }
	},
	
	{ &hf_yimp_module,
	    { "Module", "yimp.module",
		FT_STRING, BASE_NONE, NULL, 0x00,
		"Module", HFILL }
	},
	
	{ &hf_yimp_server,
	    { "Server", "yimp.server",
		FT_STRING, BASE_NONE, NULL, 0x00,
		"Server", HFILL }
	},
	
	{ &hf_yimp_parameter,
	    { "P",	"yimp.parameter",
		FT_STRING, STR_UNICODE, NULL, 0x0,
		NULL, HFILL }},
		
		{
		    &hf_yimp_continuation,
		    {
			"Continuation data",
			"yimp.continuation_data",
			FT_BYTES,
			BASE_NONE,
			NULL,
			0x0,
			NULL, HFILL
		    }
		    
		    
		},
		
		
		{ &hf_yimp_command,
		    { "Command",	"yimp.parameter",
			FT_STRING, STR_UNICODE, NULL, 0x0,
			NULL, HFILL }},
			
    };
    
    
    static gint *ett[] = {
	&ett_yimp,
	&ett_yimp_tlv_header,
    };
    
    static ei_register_info ei[] =
    {
	{
	    &ei_yimp_empty_payload,
	    {
		"yimp.empty.payload", PI_PROTOCOL, PI_WARN, "Empty payload", EXPFILL
	    }
	}
    };
    
    proto_yimp = proto_register_protocol
    (
	"Yate's Internal Messages Protocol",
     "YIMP",
     "yimp"
    );
    
    proto_register_field_array(proto_yimp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    
    expert_yimp = expert_register_protocol(proto_yimp);
    expert_register_field_array(expert_yimp, ei, array_length(ei));
    
    yimp_module = prefs_register_protocol(proto_yimp, NULL);
    
    
    prefs_register_bool_preference(yimp_module, "try_heuristic_first",
				   "Try heuristic sub-dissectors first",
				   "Try to decode a packet using an heuristic sub-dissector before "
				   "using a sub-dissector "
				   "registered to a specific port", &yimp_heuristic);
}


void
proto_reg_handoff_yimp(void)
{
    
    yimp_handle = find_dissector("yimp");
    heur_dissector_add("udp", dissect_yimp_heur, "YIMP over UDP", "yimp_udp", proto_yimp, HEURISTIC_ENABLE);
    heur_dissector_add("tcp", dissect_yimp_tcp_heur, "YIMP over TCP", "yimp_tcp", proto_yimp, HEURISTIC_ENABLE);
    
}

















