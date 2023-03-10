
#include <glib/gprintf.h>
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
static int hf_yimp_filter_name = -1;
static int hf_yimp_filter_value = -1;
static int hf_yimp_type = -1;
static int hf_yimp_debug_level = -1;

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

#define YATE_MSG_TAG "yate-msg"


typedef enum
{
    Data        = 1,
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
    Output,
    Debug,
    Quit1,
    Quit2,
    Status1,
    Status2,
    Ping1,
    Ping2,
    Connect,
    Uninstall1,
    Uninstall2,
    Unwatch1,
    Unwatch2,
} yate_cmd;

struct dict {
    yate_cmd cmd;
    const char *str;
};

static const struct dict yate_cmd_dict[] = {
    {Data, "%%<data"},
    {Message1, "%%>message"},
    {Message2, "%%<message"},
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
    {Output, "%%>output"},
    {Debug, "%%>debug"},
    {Quit1, "%%>quit"},
    {Quit2, "%%<quit"},
    {Status1, "%%>status"},
    {Status2, "%%<status"},
    {Ping1, "%%<ping"},
    {Ping2, "%%>ping"},
    {Connect, "%%>connect"},
    {Uninstall1, "%%>uninstall"},
    {Uninstall2, "%%<uninstall"},
    {Unwatch1, "%%>unwatch"},
    {Unwatch2, "%%<unwatch"},
    {0, 0}
};

typedef enum {
    SUBMITTED = 0,
    RETURNED = 1
} yimp_proceed_t;

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
char* replace(char* str, const char* a, char b)
{
    char *p = 0;
    int len = strlen(str);
    int lenA = strlen(a);

    if (!lenA)
	return str;

    for (p = str; (p = strstr(p, a)); ++p) {
	if (lenA != 1)
	    memmove(p + 1, p + lenA, len - (p - str));
	*p = b;
    }
    str[len] = '\0';
    return str;
}

int len_utf8(const char* value, guint32 maxChar)
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

    while ((c = (unsigned char) *value++)) {
	if (more) {
	    if ((c & 0xc0) != 0x80)
		return -1;
	    val = (val << 6) | (c & 0x3f);
	    if(!--more) {
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
	else if (c < 0xe0) {
	    min = 0x80;
	    val = c & 0x1f;
	    more = 1;
	}
	else if (c < 0xf0) {
	    min = 0x800;
	    val = c & 0x0f;
	    more = 2;
	}
	else if (c < 0xf8) {
	    min = 0x10000;
	    val = c & 0x07;
	    more = 3;
	}
	else if (c < 0xfc) {
	    min = 0x200000;
	    val = c & 0x03;
	    more = 4;
	}
	else if (c < 0xfe) {
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


/* Dissect TLV header for UDP messages (message sniffer) */
static int
dissect_tlvs( proto_tree *yimp_tree, tvbuff_t *tvb, int offset)
{
    guint8 tlv_type = 0;
    guint8 tlv_length = 0;
    guint totalLen = tvb_reported_length(tvb);

    for ( ; offset < totalLen - 2; ) { // need a minimum of 2 bytes for T and L

	tlv_type = tvb_get_guint8(tvb, offset++);
	tlv_length = tvb_get_guint8(tvb, offset++);

	switch (tlv_type) {
	    case YSNIFF_RESULT:
		proto_tree_add_item(yimp_tree, hf_yimp_tlv_result, tvb, offset, tlv_length, ENC_BIG_ENDIAN);
		break;
	    case YSNIFF_THREAD_ADDR:
		proto_tree_add_item(yimp_tree, hf_yimp_tlv_threadpointer, tvb, offset, tlv_length, ENC_BIG_ENDIAN);
		break;
	    case YSNIFF_THREAD_NAME:
		proto_tree_add_item(yimp_tree, hf_yimp_tlv_threadname, tvb, offset, tlv_length, ENC_BIG_ENDIAN );
		break;
	    case YSNIFF_DATA:
		proto_tree_add_item(yimp_tree, hf_yimp_tlv_data, tvb, offset, tlv_length, ENC_BIG_ENDIAN);
		break;
	    case YSNIFF_BROADCAST:
		proto_tree_add_item(yimp_tree, hf_yimp_tlv_broadcast, tvb, offset, tlv_length, ENC_BIG_ENDIAN);
		break;
	    case YSNIFF_FINAL_TAG:
		/* Finished parsing TLVs, update offset and return*/
		offset += tlv_length;
		return offset;
	    default:
		/* Report unknown type*/
		break;
	}
	offset += tlv_length;
    }
    return offset;
}

static int get_yate_cmd(tvbuff_t *tvb, proto_tree *yimp_tree, int* offset)
{
    const struct dict* d = yate_cmd_dict;
    for (; d->str; d++) {
	if(tvb_strncaseeql(tvb, *offset, d->str, strlen(d->str)) == 0) {
	    proto_tree_add_item(yimp_tree, hf_yimp_command, tvb, *offset,
		    strlen(d->str), ENC_UTF_8 | ENC_NA);
	    *offset = *offset + strlen(d->str);
	    return d->cmd;
	}
    }
    return 0;
}

static unsigned int get_num(tvbuff_t* tvb, guint len_tvb, int* offset)
{
    unsigned int num = 0;
    guint8 tmp = 0;
    int idx = *offset;
    while (1) {
	tmp = tvb_get_guint8(tvb, idx++);
	num = (num << 7) | (tmp & 0x7f);
	if (!(tmp & 0x80) || idx >= len_tvb)
	    break;
    }
    *offset = idx;
    return num;
}

struct elem {
    unsigned int offset;
    const char* str;
    unsigned int len;
    unsigned int lenUtf8;
};

static gboolean get_entry(tvbuff_t* tvb, guint len_tvb, int* offset,
	struct elem* array, unsigned int idx)
{
    unsigned int num = get_num(tvb, len_tvb, offset);
    unsigned int isStr = !!(num & 1);

    array[idx].offset = *offset;
    array[idx].len = num;

    if (!num) {
	array[idx].str = 0;
	array[idx].lenUtf8 = 0;
	array[idx].len = 0;
	return TRUE;
    }
    num = (num - 1) / 2;
    array[idx].len = num;
    if (num > len_tvb - (*offset))
	return FALSE;
    if (isStr) {
	// string
	array[idx].str = (const char *) tvb_get_string_enc(wmem_packet_scope(), tvb, *offset, num, ENC_UTF_8);
    }
    else {
	// binary data block, need hexifying
	// TODO
	array[idx].str = 0;
    }

    array[idx].lenUtf8 = len_utf8(array[idx].str, 0x10ffff);
    if (array[idx].lenUtf8 == -1)
	array[idx].lenUtf8 = strlen(array[idx].str);

    *offset += num;
    return TRUE;
}

static const char* build_line_str(struct elem* array, unsigned int array_len, unsigned int lines,
            unsigned int cols, unsigned int curCol, unsigned int* max_line_lengths, unsigned int line_len)
{
    char* str = wmem_alloc0(wmem_packet_scope(), line_len + cols);
    memset(str, 0, line_len + cols);
    unsigned int i = 0;
    unsigned int padIdx = 0;
    unsigned int cpyIdx = 0;

    for ( i = curCol; i < array_len; i += lines) {
	if (i != curCol)
	    str[cpyIdx++] = ' ';
	if (array[i].str)
	    memcpy(str + cpyIdx, array[i].str, array[i].len);
	cpyIdx += array[i].len;
	padIdx = 0;
	if (array[i].lenUtf8 < max_line_lengths[i/lines]) {
	    // pad with spaces
	    while (padIdx < max_line_lengths[i/lines] - array[i].lenUtf8) {
		str[cpyIdx++] = ' ';
		padIdx++;
	    }
	}
	wmem_free(wmem_packet_scope(), (void*)array[i].str);
	array[i].str = 0;
    }
    str[cpyIdx <  line_len + lines ? cpyIdx :  line_len + lines - 1] = '\0';
    return str;
}

static int parse_rows(proto_tree *yimp_tree, packet_info *pinfo, tvbuff_t *tvb,
        int offset, unsigned int cols, unsigned int lines)
{
    if (0 == cols * lines)
	return offset;
    struct elem* array = 0;
    unsigned int num_elem = cols * lines;
    unsigned int idx = 0;
    unsigned int lIdx = 0;
    unsigned int cIdx = 0;
    unsigned int eLen = 0;
    guint len_tvb = tvb_reported_length(tvb);
    unsigned int* max_len = 0;
    proto_tree* records_tree = 0;
    proto_tree* line_tree = 0;
    int init_offset = offset;
    const char* str = 0;
    unsigned int max_line_len = 0;
    // table: 4 cols , 3 lines
    // a  | b  | c  | d
    // a1 | b1 | c1 | d1
    // a2 | b2 | c2 | d2
    // will be transmitted as array: a a1 a2 b b1 b2 c c1 c2 d d1 d2
    // and we will display it as
    // R: a  b  c  d
    // R: a1 b1 c1 d1
    // R: a2 b2 c2 d2
    array = malloc(num_elem * sizeof(struct elem));
    memset(array, 0, num_elem * sizeof(struct elem));

    for ( idx = 0; idx < num_elem; idx++) {
	if (!get_entry(tvb, len_tvb, &offset, array, idx))
	    break;
    }
    if (idx < num_elem) {
	if (pinfo->can_desegment) {
	    pinfo->desegment_offset = offset ;
	    pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
	    for (idx = 0; idx < num_elem; idx++) {
		if (array[idx].str)
		    wmem_free(wmem_packet_scope(),(void*) array[idx].str);
	    }
	    free(array);
	    return offset;
	}
    }
    // determine max_len for each column because we want to pad them
    // for the sake of prettiness
    max_len = malloc(cols * sizeof(unsigned int));
    memset(max_len, 0, cols * sizeof(unsigned int));
    for (cIdx = 0; cIdx < num_elem; cIdx += lines) {
	for (lIdx = 0; lIdx < lines; lIdx++) {
	    eLen = array[lIdx + cIdx].lenUtf8;
	    if (eLen > max_len[cIdx / lines])
		max_len[cIdx / lines] = eLen;
	}
    }

    // compute max length of  for each line line
    for (cIdx = 0; cIdx < cols; cIdx++)
	max_line_len += max_len[cIdx];
    str = (const char *)tvb_get_string_enc(wmem_packet_scope(), tvb, init_offset, len_tvb - init_offset, ENC_UTF_8);
    records_tree = proto_tree_add_string(yimp_tree, hf_yimp_message, tvb, init_offset, len_tvb - init_offset, str);
    proto_item_set_text(records_tree, "RECORDS");
    line_tree = proto_item_add_subtree(records_tree, ett_yimp);
    // now add entries to trees
    for (lIdx = 0, cIdx = 0; cIdx < cols && lIdx < lines; cIdx++, lIdx++) {
	str = build_line_str(array, num_elem, lines, cols, cIdx, max_len, max_line_len);
	proto_tree_add_string(line_tree, hf_yimp_line, tvb, array[cIdx].offset, strlen(str) , str);
    }
    free(array);
    free(max_len);

    return offset;
}

static int
dissect_ymsg( proto_tree *yimp_tree, packet_info *pinfo, tvbuff_t *tvb,
		int offset, int line_len, gint next_line_offset)
{
    guint len_tvb = tvb_reported_length(tvb);
    gint pos = -1;
    const char* str = 0;
    const char* params = 0;
    gint param_len = 0;
    proto_item *tlv_tree = 0;
    proto_tree *param_tree = 0;

    if (!(tvb && yimp_tree && pinfo && ((guint)offset <  len_tvb)))
	return offset;

    if (line_len == -1)
	line_len = offset + tvb_find_line_end(tvb, offset, -1, &next_line_offset, FALSE);

#define EXTRACT_FIXED(id,enc) { \
    if ((pos = tvb_find_guint8(tvb, offset, -1, ':')) >= offset) { \
	proto_tree_add_item(yimp_tree, id, tvb, offset, pos - offset, enc); \
	offset = pos + 1; \
    }\
}

    int cmd = get_yate_cmd(tvb,yimp_tree,&offset);
    offset += 1; // command is followed by ':'
    switch (cmd) {
	case Message1:
	    // %%>message:<id>:<time>:<name>:<retvalue>[:<key>=<value>...
	    // intentional fall through
	case Message2:
	    // %%<message:<id>:<processed>:[<name>]:<retvalue>[:<key>=<value>...]
	{
	    EXTRACT_FIXED(hf_yimp_id, ENC_UTF_8 | ENC_NA);
	    if (Message1 == cmd)
		EXTRACT_FIXED(hf_yimp_time, ENC_UTF_8 | ENC_NA)
	    else
		EXTRACT_FIXED(hf_yimp_processed, ENC_UTF_8 | ENC_NA);

	    // name needs special handling
	    pos = tvb_find_guint8(tvb, offset, -1, ':');
	    if (pos >= offset) {
		proto_tree_add_item(yimp_tree, hf_yimp_name, tvb, offset, pos - offset, ENC_UTF_8|ENC_NA);
		str = (const char *)tvb_get_string_enc(wmem_packet_scope(), tvb, offset, pos - offset, ENC_ASCII);
		col_add_fstr(pinfo->cinfo, COL_INFO, "Message: %s", str);
		offset = pos + 1;
	    }
	    // retvalue needs escaping
	    pos = tvb_find_guint8(tvb, offset, -1, ':');
	    if (pos >= offset) {
		str = (const char *)tvb_get_string_enc(wmem_packet_scope(), tvb, offset, pos - offset, ENC_ASCII);
		str = replace((char*)str, "%J", ' ');
		proto_tree_add_string(yimp_tree, hf_yimp_retvalue, tvb, offset, pos - offset, str);
		offset = pos + 1;
	    }
	    if (offset >= len_tvb || offset >= line_len)
		break;
	    // parameter parsing
	    // find first non-whitespace character after ':' until the next line
	    pos = tvb_skip_wsp(tvb, offset, line_len - offset);
	    params = (const char *)tvb_get_string_enc(wmem_packet_scope(), tvb, pos, line_len - pos /*offset + param_len - pos*/, ENC_UTF_8);
	    if (!strlen(params))
		break;
	    // add parameters sub-tree
	    tlv_tree = proto_tree_add_string(yimp_tree, hf_yimp_message, tvb, pos, line_len - pos, params);
	    proto_item_set_text(tlv_tree, "PARAMETERS");
	    param_tree = proto_item_add_subtree(tlv_tree, ett_yimp);
	    str = strtok((char*)params, ":");
	    while (str != NULL) {
		param_len = strlen(str); // save this before unescape because length will shrink after it
		str = replace((char*)str, "%z", ':');
		proto_tree_add_string(param_tree, hf_yimp_parameter, tvb, offset, param_len, str);
		offset += param_len + 1;
		str = strtok(NULL, ":");
	    }
	    break;
	}
	case Version1:
	    // intentional fall through
	case Version2:
	    str = (const char *)tvb_get_string_enc(wmem_packet_scope(), tvb, offset, line_len - offset, ENC_ASCII);
	    proto_tree_add_item(yimp_tree, hf_yimp_version, tvb, offset, line_len - offset, ENC_ASCII | ENC_NA );
	    offset = line_len;
	    col_append_fstr(pinfo->cinfo, COL_INFO, "Version: %s ", str);
	    break;
	case Auth1:
	    // intentional fall through
	case Auth2:
	    pos = tvb_find_guint8(tvb, offset, -1, ':');
	    if (pos >= offset) {
		str = (const char *)tvb_get_string_enc(wmem_packet_scope(), tvb, offset, pos - offset, ENC_ASCII);
		proto_tree_add_string(yimp_tree, hf_yimp_timestamp, tvb, offset, pos - offset, str);
		col_append_fstr(pinfo->cinfo, COL_INFO, "Auth: %s ", str);
		offset = pos + 1;
	    }
	    if (line_len >= offset) {
		str = (const char *)tvb_get_string_enc(wmem_packet_scope(), tvb, offset, line_len - offset, ENC_ASCII);
		param_tree = proto_item_add_subtree(yimp_tree, ett_yimp);
		proto_tree_add_string(param_tree, hf_yimp_hash, tvb, offset, line_len - offset, str);
		offset = line_len;
	    }
	    break;
	case Watch1:
	    // %%>watch:<name>
	    // intentional fallthrough
	    if (line_len >= offset) {
		str = (const char*) tvb_get_string_enc(wmem_packet_scope(), tvb, offset, line_len - offset, ENC_ASCII);
		param_tree = proto_item_add_subtree(yimp_tree, ett_yimp);
		proto_tree_add_string(param_tree, hf_yimp_parameter_watch, tvb, offset, line_len - offset, str);
		col_add_fstr(pinfo->cinfo, COL_INFO, "Watch: %s ", str);
		offset = line_len;
	    }
	    break;
	case Watch2:
	    // %%<watch:<name>:<success>
	    pos = tvb_find_guint8(tvb, offset, -1, ':');
	    if (pos >= offset) {
		str = (const char*) tvb_get_string_enc(wmem_packet_scope(), tvb, offset, pos - offset, ENC_ASCII);
		param_tree = proto_item_add_subtree(yimp_tree, ett_yimp);
		proto_tree_add_string(param_tree, hf_yimp_parameter_watch, tvb, offset, pos - offset, str);
		col_add_fstr(pinfo->cinfo, COL_INFO, "Watch: %s ", str);
		offset = pos + 1;

		if (line_len >= offset) {
		    str = (const char*) tvb_get_string_enc(wmem_packet_scope(), tvb, offset, line_len - offset, ENC_ASCII);
		    proto_tree_add_string(param_tree, hf_yimp_parameter_success, tvb, offset, line_len - offset, str);
		    offset = line_len;
		}
	    }
	    break;
	case Install1:
	    // %%<install:<priority>:<name>:<success>
	    // intentional fall through
	case Install2:
	    // %%>install:[<priority>]:<name>[:<filter-name>[:<filter-value>]]
	    EXTRACT_FIXED(hf_yimp_install_priority, ENC_UTF_8 | ENC_NA);

	    pos = tvb_find_guint8(tvb, offset, -1, ':');
	    pos = pos == -1 ? line_len : pos;
	    if (pos >= offset) {
		str = (const char*) tvb_get_string_enc(wmem_packet_scope(), tvb, offset, pos - offset, ENC_ASCII);
		proto_tree_add_string(yimp_tree, hf_yimp_name, tvb, offset, pos - offset, str);
		col_add_fstr(pinfo->cinfo, COL_INFO, "Install: %s ", str);
		offset = pos == line_len ? line_len : pos + 1;
	    }

	    if (Install1 == cmd) {
		if (line_len > offset) {
		    str = (const char*) tvb_get_string_enc(wmem_packet_scope(), tvb, offset, line_len - offset, ENC_ASCII);
		    proto_tree_add_string(yimp_tree, hf_yimp_parameter_success, tvb, offset, line_len - offset, str);
		    offset = line_len;
		}
	    }
	    else if (line_len > offset) {
		EXTRACT_FIXED(hf_yimp_filter_name, ENC_UTF_8 | ENC_NA);
		if (line_len > offset) {
		    str = (const char*) tvb_get_string_enc(wmem_packet_scope(), tvb, offset, line_len - offset, ENC_UTF_8);
		    proto_tree_add_string(yimp_tree, hf_yimp_filter_value, tvb, offset, line_len - offset, str);
		    offset = line_len;
		}
	    }
	    break;
	case Setlocal1:
	    // %%>setlocal:<name>:<value>
	    // intentional fall-through
	case Setlocal2:
	    // %%<setlocal:<name>:<value>:<success>
	    pos = tvb_find_guint8(tvb, offset, -1, ':');
	    if (pos >= offset) {
		str = (const char*) tvb_get_string_enc(wmem_packet_scope(), tvb, offset, pos - offset, ENC_ASCII);
		proto_tree_add_string(yimp_tree, hf_yimp_name, tvb, offset, pos - offset, str);
		col_add_fstr(pinfo->cinfo, COL_INFO, "Setlocal: %s ", str);
		offset = pos + 1;
	    }
	    pos = Setlocal2 == cmd ? tvb_find_guint8(tvb, offset, -1, ':') : line_len;
	    if (pos >= offset) {
		str = (const char*) tvb_get_string_enc(wmem_packet_scope(), tvb, offset, pos - offset, ENC_ASCII);
		proto_tree_add_string(yimp_tree, hf_yimp_parameter_value, tvb, offset, pos - offset, str);
		offset = cmd == Setlocal2 ? pos + 1 : line_len;
	    }
	    if (Setlocal2 == cmd && offset < line_len) {
		str = (const char*) tvb_get_string_enc(wmem_packet_scope(), tvb, offset, line_len - offset, ENC_ASCII);
		proto_tree_add_string(yimp_tree, hf_yimp_parameter_success, tvb, offset, line_len - offset, str);
		offset = line_len;
	    }
	    break;
	case Output:
	    // %%>output:arbitrary unescaped string
	    str = (const char *)tvb_get_string_enc(wmem_packet_scope(), tvb, offset, line_len - offset, ENC_UTF_8);
	    proto_tree_add_item(yimp_tree, hf_yimp_output, tvb, offset, line_len - offset, ENC_UTF_8 | ENC_NA );
	    col_append_fstr(pinfo->cinfo, COL_INFO, "Output: %s ", str);
	    offset = line_len;
	    break;
	case Debug:
	    // %%>debug:<level>:arbitrary escaped string
	    EXTRACT_FIXED(hf_yimp_debug_level, ENC_UTF_8 | ENC_NA);
	    str = (const char *)tvb_get_string_enc(wmem_packet_scope(), tvb, offset, line_len - offset, ENC_UTF_8);
	    proto_tree_add_item(yimp_tree, hf_yimp_output, tvb, offset, line_len - offset, ENC_UTF_8 | ENC_NA );
	    col_append_fstr(pinfo->cinfo, COL_INFO, "Debug: %s ", str);
	    offset = line_len;
	    break;
	case Quit1:
	    // intentional fall through
	case Quit2:
	    col_append_fstr(pinfo->cinfo, COL_INFO, "Quit ");
	    break;
	case Status1:
	    // intentional fall through
	case Status2:
	    str = (const char *)tvb_get_string_enc(wmem_packet_scope(), tvb, offset, line_len - offset, ENC_ASCII);
	    proto_tree_add_item(yimp_tree, hf_yimp_status, tvb, offset, line_len - offset, ENC_ASCII | ENC_NA );
	    col_add_fstr(pinfo->cinfo, COL_INFO, "Status: %s ", str);
	    offset = line_len;
	    break;
	case Ping1:
	    // intentional fall through
	case Ping2:
	    str = (const char *)tvb_get_string_enc(wmem_packet_scope(), tvb, offset, line_len - offset, ENC_ASCII | ENC_NA);
	    proto_tree_add_item(yimp_tree, hf_yimp_ping, tvb, offset, line_len - offset, ENC_ASCII | ENC_NA );
	    col_add_fstr(pinfo->cinfo, COL_INFO, "Ping: %s ", str);
	    offset = line_len;
	    break;
	case Connect:
	    // %%>connect:<role>[:<id>][:<type>]
	    pos = tvb_find_guint8(tvb, offset, -1, ':');
	    if (pos >= offset) {
		str = (const char *)tvb_get_string_enc(wmem_packet_scope(), tvb, offset, pos - offset, ENC_ASCII);
		proto_tree_add_item(yimp_tree, hf_yimp_role, tvb, offset, pos - offset, ENC_ASCII | ENC_NA );
		col_add_fstr(pinfo->cinfo, COL_INFO, "Connect: %s ", str);
		offset = pos + 1;

		pos = tvb_find_guint8(tvb, offset, -1, ':');
		pos = pos == -1 ? line_len : pos;
		if (pos > offset) {
		    proto_tree_add_item(yimp_tree, hf_yimp_id, tvb, offset, pos - offset, ENC_UTF_8 | ENC_NA);
		    offset = pos == line_len ? line_len : pos + 1;
		}
		if (line_len > offset) {
		    proto_tree_add_item(yimp_tree, hf_yimp_type, tvb, offset, line_len - offset, ENC_UTF_8 | ENC_NA);
		    offset = line_len;
		}
	    }
	    else {
		str = (const char *)tvb_get_string_enc(wmem_packet_scope(), tvb, offset, line_len - offset, ENC_ASCII);
		proto_tree_add_item(yimp_tree, hf_yimp_role, tvb, offset, line_len - offset, ENC_ASCII | ENC_NA );
		col_add_fstr(pinfo->cinfo, COL_INFO, "Connect: %s ", str);
		offset = line_len;
	    }
	    break;
	case Uninstall1:
	    // %%>uninstall:<name>
	    str = (const char *)tvb_get_string_enc(wmem_packet_scope(), tvb, offset, line_len - offset, ENC_ASCII);
	    proto_tree_add_item(yimp_tree, hf_yimp_name, tvb, offset, line_len - offset, ENC_ASCII | ENC_NA );
	    col_add_fstr(pinfo->cinfo, COL_INFO, "Uninstall: %s ", str);
	    offset = line_len;
	    break;
	case Uninstall2:
	    // %%<uninstall:<priority>:<name>:<success>
	    EXTRACT_FIXED(hf_yimp_install_priority, ENC_UTF_8 | ENC_NA);
	    pos = tvb_find_guint8(tvb, offset, -1, ':');
	    if (pos >= offset) {
		str = (const char*) tvb_get_string_enc(wmem_packet_scope(), tvb, offset, pos - offset, ENC_ASCII);
		proto_tree_add_string(yimp_tree, hf_yimp_name, tvb, offset, pos - offset, str);
		col_add_fstr(pinfo->cinfo, COL_INFO, "Uninstall: %s ", str);
		offset = pos + 1;
	    }
	    if (offset < line_len) {
		proto_tree_add_item(yimp_tree, hf_yimp_parameter_success, tvb, offset, line_len - offset, ENC_ASCII | ENC_NA );
		offset = line_len;
	    }
	    break;
	case Unwatch1:
	    // %%>unwatch:<name>
	    str = (const char *)tvb_get_string_enc(wmem_packet_scope(), tvb, offset, line_len - offset, ENC_ASCII);
	    proto_tree_add_item(yimp_tree, hf_yimp_parameter_watch, tvb, offset, line_len - offset, ENC_ASCII | ENC_NA );
	    col_add_fstr(pinfo->cinfo, COL_INFO, "Unwatch: %s ", str);
	    offset = line_len;
	    break;
	case Unwatch2:
	    // %%<unwatch:<name>:<success>
	    pos = tvb_find_guint8(tvb, offset, -1, ':');
	    if (pos >= offset) {
		str = (const char*) tvb_get_string_enc(wmem_packet_scope(), tvb, offset, pos - offset, ENC_ASCII);
		proto_tree_add_string(yimp_tree, hf_yimp_parameter_watch, tvb, offset, pos - offset, str);
		col_add_fstr(pinfo->cinfo, COL_INFO, "Unwatch: %s ", str);
		offset = pos + 1;
	    }
	    if (offset < line_len)
		proto_tree_add_item(yimp_tree, hf_yimp_parameter_success, tvb, offset, line_len - offset, ENC_UTF_8 | ENC_NA );
	    break;
	case Data:
	{
	    // %%<data:cols:lines\r\n{[num val][num val]} where {} array contains cols * lines entries
	    // num is length(val) + 2 + type, where type = 1 for string and type = 2 for binary
	    pos  = tvb_find_guint8(tvb, offset, line_len - offset, ':');
	    guint cols = 0;
	    guint lines = 0;
	    if (pos >= offset) {
		str = (const char *) tvb_get_string_enc(wmem_packet_scope(), tvb, offset, pos - offset, ENC_ASCII);
		proto_tree_add_item(yimp_tree, hf_yimp_data_columns, tvb, offset, pos - offset, ENC_ASCII | ENC_NA);
		cols = atoi(str);
		offset = pos + 1;
	    }
	    // lines is until \r\n
	    str = (const char *) tvb_get_string_enc(wmem_packet_scope(), tvb, offset, line_len - offset, ENC_ASCII);
	    proto_tree_add_item(yimp_tree, hf_yimp_data_lines, tvb, offset,  line_len - offset, ENC_ASCII | ENC_NA);
	    lines = atoi(str);
	    col_append_fstr(pinfo->cinfo, COL_INFO, "Data: %d Columns x %d Lines ", cols, lines);
	    offset = next_line_offset;
	    // nothing to parse
	    if (cols * lines == 0)
		break;
	    offset = parse_rows(yimp_tree, pinfo, tvb, offset, cols, lines);
	    break;
	}
	default:
	    proto_tree_add_item(yimp_tree, hf_yimp_tlv_dataremain, tvb, offset, line_len - offset, ENC_ASCII);
	    offset = line_len;
	    break;
    }
    return offset;
}


static gboolean
dissect_yimp_tcp_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    int offset = 0;
    gint lineLen = 0;
    gint length = 0;
    gint next_line = 0;
    proto_item *ti = 0;
    proto_tree *yimp_tree = 0;

    // check if line starts with '%%' conforming with the YATE exmodul protocol
    if ((tvb_captured_length(tvb) > 1) && tvb_strncaseeql(tvb, 0, "%%", 2) != 0)
	return FALSE;

    col_clear(pinfo->cinfo, COL_PROTOCOL);
    col_clear(pinfo->cinfo, COL_INFO);

    lineLen  = tvb_find_line_end(tvb, offset, -1, &next_line, TRUE);
    if (lineLen == -1) {
	if (pinfo->can_desegment) {
	    pinfo->desegment_offset = offset ;
	    pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
	    return TRUE;
	}
    }

    length = tvb_reported_length_remaining(tvb, offset);
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "YIMP");
    col_add_fstr(pinfo->cinfo, COL_INFO, "Yate's Internal Messages Protocol");

    // lineLen > 3 because a Yate message starts with %% and > or < 
    while(length > 0 && lineLen >= 3) {
	ti = proto_tree_add_protocol_format(tree, proto_yimp, tvb, 0, lineLen, "Yate's Internal Messages Protocol (%d bytes)",next_line - offset);
	yimp_tree = proto_item_add_subtree(ti, ett_yimp);
	/* decode encoded YATE message */
	offset = dissect_ymsg(yimp_tree, pinfo, tvb, offset, lineLen, next_line);
	// adjust offset to skip over CRLF
	if (offset < next_line)
	    offset = next_line;
	length -= offset;
	if (length <= 0)
	    return TRUE;
	// find new line
	lineLen  = tvb_find_line_end(tvb, offset, -1, &next_line, TRUE);
	if (lineLen == -1) {
	    if (pinfo->can_desegment) {
		pinfo->desegment_offset = offset ;
		pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
	    }
	    return TRUE;
	}
    }

    return TRUE;
}

static int
dissect_yimp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    conversation_t *conversation;
    guint len_tvb = 0;
    proto_item *ti;
    proto_tree *yimp_tree;
    guint32 offset = 0;

    conversation = find_or_create_conversation(pinfo);
    conversation_set_dissector(conversation, yimp_handle);

    /* Add info for protocol in upper third part of the windon, in the 'Protocol' column*/
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "YIMP");
    col_add_fstr(pinfo->cinfo, COL_INFO, "Yate's Internal Messages Protocol");

    /* Get length of YIMP payload and display it in the tree*/
    len_tvb = tvb_reported_length(tvb);
    /* Add YIMP proto to the proto tree*/
    ti = proto_tree_add_protocol_format(tree, proto_yimp, tvb, 0, -1,
		"Yate's Internal Messages Protocol (%d bytes)", len_tvb);

    /* Create the YIMP subtree*/
    yimp_tree = proto_item_add_subtree(ti, ett_yimp);

    /* skip over yate-msg string at the start of payload*/
    offset += strlen(YATE_MSG_TAG);

    /* start parsing*/
    /* decode TLV part first*/
    offset = dissect_tlvs(yimp_tree, tvb, offset);
    /* decode encoded YATE message */
    offset = dissect_ymsg(yimp_tree, pinfo, tvb, offset, -1, -1);
    return tvb_reported_length(tvb);
}

/**
 * Dissect message sniffer packets
 */
static gboolean
dissect_yimp_udp_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    if( (tvb_captured_length(tvb) < strlen(YATE_MSG_TAG)) ||
	    (tvb_strncaseeql(tvb, 0, YATE_MSG_TAG, strlen(YATE_MSG_TAG)) != 0) )
	return FALSE;
    dissect_yimp(tvb, pinfo, tree, data);
    return (TRUE);
}

/* Register the protocol with Wireshark.
 *
 * This format is required because a script is used to build the C function that
 * calls all the protocol registration.
 */
void
proto_register_yimp(void )
{
    module_t	*yimp_module;
    expert_module_t *expert_yimp;

    /* Setup list of header fields  See Section 1.5 of README.dissector for
     * details. */
    static hf_register_info hf[] = {
	{ &hf_yimp_signature,
	    { "Signature", "yimp.signature", FT_STRING, BASE_NONE, NULL, 0x00,
		"Dissector for Yate's internal messages", HFILL }},
	{ &hf_yimp_tlv_type,
	    { "TlvType","yimp.tlv.type", FT_UINT8, BASE_HEX | BASE_EXT_STRING, NULL,
		0x0, NULL, HFILL }},
	{ &hf_yimp_tlv_length,
	    { "TlvLength","yimp.tlv.length", FT_UINT8, BASE_HEX, NULL,
		0x0, NULL, HFILL }},
	{ &hf_yimp_tlv_dataremain,
	    { "Garbage","yimp.tlv.data", FT_STRING, BASE_NONE, NULL,
		0x0, NULL, HFILL }},
	{ &hf_yimp_output,
	    { "Output","yimp.tlv.data", FT_STRING, BASE_NONE, NULL,
		0x0, NULL, HFILL }},
	{ &hf_yimp_line,
	    { "R","yimp.r", FT_STRING, BASE_NONE, NULL,
		0x0, NULL, HFILL }},
	{ &hf_yimp_element,
	    { "Element","yimp.tlv.data", FT_STRING, BASE_NONE, NULL,
		0x0, NULL, HFILL }},
	{ &hf_yimp_tlv_result,
	    { "Direction", "yimp.result", FT_UINT8, BASE_DEC, VALS(yimp_result), 0x0,
		"Type of the encoded message", HFILL }},
	{ &hf_yimp_tlv_broadcast,
	    { "Broadcast", "yimp.broadcast", FT_UINT8, BASE_DEC, VALS(yimp_broadcast), 0x0,
		"Broadcast tag", HFILL }},
	{ &hf_yimp_tlv_threadpointer,
	    { "ThreadPointer", "yimp.thread_pointer", FT_STRING, BASE_NONE, NULL, 0x0,
		"Pointer to the current thread", HFILL }},
	{ &hf_yimp_tlv_data,
	    { "DataPointer", "yimp.data_pointer", FT_STRING, BASE_NONE, NULL, 0x0,
		"Pointer to data", HFILL }},
	{ &hf_yimp_tlv_threadname,
	    { "ThreadName", "yimp.thread_name", FT_STRING, BASE_NONE, NULL, 0x00,
		"Name of the current thread", HFILL }},
	{ &hf_yimp_tlv_final,
	    {"FinalTag", "yimp.final_tag", FT_UINT8, BASE_HEX, NULL, 0x0,
		"Final tag", HFILL }},
	{ &hf_yimp_messagename,
	    { "Message Name", "yimp.message_name", FT_STRING, BASE_NONE, NULL, 0x00,
		"Name of the current message", HFILL }},
	{ &hf_yimp_parameter_data,
	    { "Data", "yimp.data", FT_STRING, BASE_NONE, NULL, 0x00,
		"Data", HFILL }},
	{ &hf_yimp_message,
	    { "Message",  "yimp.message", FT_STRING, BASE_NONE, NULL, 0x0,
		"Message", HFILL }},
	{ &hf_yimp_tlvs,
	    { "TLVS",  "yimp.tlvs", FT_STRING, BASE_NONE, NULL, 0x0,
		"TLVS", HFILL }},
	{ &hf_yimp_id,
	    { "Id",  "yimp.id",	FT_STRING, BASE_NONE, NULL, 0x0,
		"Obscure unique message ID string generated by Yate", HFILL }},
	{ &hf_yimp_install_priority,
	    { "Priority",  "yimp.priority", FT_STRING, BASE_NONE, NULL, 0x0,
		"Priority in chain, use default (100) if missing", HFILL }},
	{ &hf_yimp_time,
	    { "Time",  "yimp.time", FT_STRING, BASE_NONE, NULL, 0x0,
		"Time (in seconds) the message was initially created", HFILL }},
	{ &hf_yimp_timestamp,
	    { "Timestamp",  "yimp.timestamp", FT_STRING, BASE_NONE, NULL, 0x0,
		"Time (in seconds) the message was initially created", HFILL }},
	{ &hf_yimp_data_columns,
	    { "Columns",  "yimp.columns", FT_STRING, BASE_NONE, NULL, 0x0,
		"Columns", HFILL }},
	{ &hf_yimp_data_lines,
	    { "Lines",  "yimp.lines", FT_STRING, BASE_NONE, NULL, 0x0,
		"Lines", HFILL }},
	{ &hf_yimp_hash,
	    { "Hash",  "yimp.hash", FT_STRING, BASE_NONE, NULL, 0x0,
		"Hash", HFILL }},
	{ &hf_yimp_parameter_watch,
	    { "Name",  "yimp.name", FT_STRING, BASE_NONE, NULL, 0x0,
		"Name of the messages for that a watcher should be installed", HFILL }},
	{ &hf_yimp_role,
	    { "Role",  "yimp.role", FT_STRING, BASE_NONE, NULL, 0x0,
		NULL, HFILL }},
	{ &hf_yimp_name,
	    { "Name",  "yimp.name", FT_STRING, BASE_NONE, NULL, 0x0,
		"Name of the message", HFILL }},
	{ &hf_yimp_version,
	    { "Version",  "yimp.version", FT_STRING, BASE_NONE, NULL, 0x0,
		"Version", HFILL }},
	{ &hf_yimp_status,
	    { "Status",  "yimp.status", FT_STRING, BASE_NONE, NULL, 0x0,
		"Status", HFILL }},
	{ &hf_yimp_parameter_success,
	    { "Success",  "yimp.success", FT_STRING, BASE_NONE, NULL, 0x0,
		"Boolean success of operation", HFILL }},
	{ &hf_yimp_processed,
	    { "Processed",  "yimp.processed", FT_STRING, BASE_NONE, NULL, 0x0,
		"Boolean indication if the message has been processed or it should be passed to the next handler", HFILL }},
	{ &hf_yimp_parameter_value,
	    { "Value",  "yimp.value", FT_STRING, BASE_NONE, NULL, 0x0,
		"New value to set in the local module instance, empty to just query", HFILL }},
	{ &hf_yimp_retvalue,
	    { "retvalue",  "yimp.retvalue", FT_STRING, BASE_NONE, NULL, 0x0,
		"retvalue", HFILL }},
	{ &hf_yimp_ping,
	    { "Ping",  "yimp.ping", FT_STRING, BASE_NONE, NULL, 0x0,
		"Ping", HFILL }},
	{ &hf_yimp_nodename, 
	    { "Nodename",  "yimp.nodename", FT_STRING, BASE_NONE, NULL, 0x0,
		"Nodname of the message", HFILL }},
	{ &hf_yimp_handlers,
	    { "Handlers",  "yimp.handlers", FT_STRING, BASE_NONE, NULL, 0x0,
		"Handlers of the message", HFILL }},
	{ &hf_yimp_fulltext,
	    { "Full text", "yimp.fulltext", FT_STRING, BASE_NONE, NULL, 0x00,
		"Full text", HFILL }},
	{ &hf_yimp_test,
	    { "Test", "yimp.test", FT_STRING, BASE_NONE, NULL, 0x00,
		"Test", HFILL }},
	{ &hf_yimp_module,
	    { "Module", "yimp.module", FT_STRING, BASE_NONE, NULL, 0x00,
		"Module", HFILL }},
	{ &hf_yimp_server,
	    { "Server", "yimp.server", FT_STRING, BASE_NONE, NULL, 0x00,
		"Server", HFILL }},
	{ &hf_yimp_parameter,
	    { "P",	"yimp.parameter", FT_STRING, BASE_NONE, NULL, 0x0,
		NULL, HFILL }},
	{ &hf_yimp_continuation,
	    { "Continuation data", "yimp.continuation_data", FT_BYTES, BASE_NONE, NULL, 0x0,
		NULL, HFILL }},
	{ &hf_yimp_command,
	    { "Command", "yimp.parameter", FT_STRING, BASE_NONE, NULL, 0x0,
		NULL, HFILL }},
	{ &hf_yimp_filter_name,
	    { "Filter Name", "yimp.filter_name", FT_STRING, BASE_NONE, NULL, 0x0,
		"Filter parameter for the message", HFILL}},
	{ &hf_yimp_filter_value,
	    { "Filter Value", "yimp.filter_value", FT_STRING, BASE_NONE, NULL, 0x0,
		"Filter parameter value for the message", HFILL}},
	{ &hf_yimp_type,
	    { "Type", "yimp.type", FT_STRING, BASE_NONE, NULL, 0x0,
		"Type of data channel", HFILL}},
	{ &hf_yimp_debug_level,
	    { "Debug Level", "yimp.debug_level", FT_STRING, BASE_NONE, NULL, 0x0,
		"Debug level of message", HFILL}},
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
	&ett_yimp,
	&ett_yimp_tlv_header,
    };

    /* Setup protocol expert items */
    static ei_register_info ei[] = {
	{ &ei_yimp_empty_payload,
	  { "yimp.empty.payload", PI_PROTOCOL, PI_WARN, "Empty payload", EXPFILL } }
    };

    /* Register the protocol name and description */
    proto_yimp = proto_register_protocol( "Yate's Internal Messages Protocol",
                                          "YIMP",
                                          "yimp");

     /* Required function calls to register the header fields and subtrees */
    proto_register_field_array(proto_yimp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Required function calls to register expert items */
    expert_yimp = expert_register_protocol(proto_yimp);
    expert_register_field_array(expert_yimp, ei, array_length(ei));

    /* Register a preferences module (see section 2.6 of README.dissector
     * for more details). Registration of a prefs callback is not required
     * if there are no preferences that affect protocol registration (an example
     * of a preference that would affect registration is a port preference).
     * If the prefs callback is not needed, use NULL instead of
     * proto_reg_handoff_PROTOABBREV in the following.
     */
    yimp_module = prefs_register_protocol(proto_yimp, NULL);

    /* Register a simple example preference */
    prefs_register_bool_preference(yimp_module, "try_heuristic_first",
            "Try heuristic sub-dissectors first",
            "Try to decode a packet using an heuristic sub-dissector before "
            "using a sub-dissector registered to a specific port",
            &yimp_heuristic);
}


void
proto_reg_handoff_yimp(void)
{
    yimp_handle = find_dissector("yimp");
    heur_dissector_add("udp", dissect_yimp_udp_heur, "YIMP over UDP", "yimp_udp", proto_yimp, HEURISTIC_ENABLE);
    heur_dissector_add("tcp", dissect_yimp_tcp_heur, "YIMP over TCP", "yimp_tcp", proto_yimp, HEURISTIC_ENABLE);
}

















