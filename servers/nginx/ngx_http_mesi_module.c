#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#ifndef LIB_GOMESI_PATH
#define LIB_GOMESI_PATH "/usr/lib/libgomesi.so"
#endif

// Mirrors Apache's MESI_MAX_CACHE_KEY_TEMPLATE: bounds the template so a
// runaway config value cannot drive unbounded allocations (the template is
// copied into per-request C strings and evaluated per cache lookup).
// Defense-in-depth: nginx's own config parser caps a single quoted
// argument at ~4090 bytes ("too long parameter"), tighter than this
// module-level check — the module cap keeps nginx consistent with the
// Apache/PHP-extension 4096 limit and stays the active guard if the
// parser limit ever changes.
#define MESI_MAX_CACHE_KEY_TEMPLATE 4096

typedef struct {
  ngx_flag_t enable_mesi;
  ngx_str_t  cache_backend;  // "" (off), "memory", "redis", "memcached"
  ngx_int_t  cache_size;     // max entries for memory cache
  ngx_int_t  cache_ttl;      // TTL in seconds
  ngx_str_t  cache_memcached_servers;  // space-separated "host:port host:port"
  ngx_str_t  cache_redis_addr;         // e.g. "localhost:6379"
  ngx_str_t  cache_redis_password;
  ngx_int_t  cache_redis_db;           // Redis database number (0-15)
  ngx_flag_t block_private_ips;        // SSRF: block private/reserved IPs (default ON)
  ngx_str_t  allowed_hosts;  // space-separated host whitelist ("" = no restriction)
  ngx_flag_t allow_private_ips_for_allowed;  // private-IP bypass for allowed_hosts (default OFF)
  ngx_str_t  cache_key_template;  // "" = URL-only DefaultCacheKey (backward compat)
} ngx_http_mesi_loc_conf_t;

typedef struct {
  ngx_str_t accumulated;
  ngx_flag_t done;
} ngx_http_html_head_filter_ctx_t;

static ngx_http_output_header_filter_pt ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt ngx_http_next_body_filter;

static ngx_int_t ngx_http_html_mesi_head_filter(ngx_http_request_t *r);
static ngx_int_t ngx_http_html_mesi_body_filter(ngx_http_request_t *r,
                                                ngx_chain_t *in);
static ngx_str_t parse(ngx_str_t input, ngx_http_request_t *r);
static ngx_int_t ngx_http_html_head_filter_init(ngx_conf_t *cf);

static void ngx_http_mesi_thread_exit(ngx_cycle_t *cycle);
static ngx_int_t ngx_http_mesi_thread_init(ngx_cycle_t *cycle);

static ngx_int_t ngx_test_content_compression(ngx_http_request_t *r);
static ngx_int_t ngx_test_is_html(ngx_http_request_t *r);

static void *ngx_http_mesi_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_mesi_merge_loc_conf(ngx_conf_t *cf, void *parent,
                                          void *child);

typedef char *(*ParseFunc)(char *, int, char *);
typedef char *(*ParseWithConfigFunc)(char *, int, char *, char *, int);
typedef char *(*ParseWithConfigExFunc)(char *, int, char *, char *, int, int);
typedef char *(*ParseWithConfigCtxFunc)(char *, int, char *, char *, int, int, char *, char *);
typedef int (*InitCacheFunc)(char *, int, int);
typedef int (*InitCacheWithConfigFunc)(char *, int, int, char *);
typedef void (*FreeCacheFunc)(void);

static void *go_module = NULL;
static ParseFunc EsiParse = NULL;
static ParseWithConfigFunc EsiParseWithConfig = NULL;
static ParseWithConfigExFunc EsiParseWithConfigEx = NULL;
static ParseWithConfigCtxFunc EsiParseWithConfigCtx = NULL;
static InitCacheFunc EsiInitCache = NULL;
static InitCacheWithConfigFunc EsiInitCacheWithConfig = NULL;
static FreeCacheFunc EsiFreeCache = NULL;
static ngx_flag_t cache_initialized = 0;
static ngx_str_t cache_last_backend = ngx_null_string;

static ngx_command_t ngx_http_mesi_commands[] = {
    {ngx_string("enable_mesi"), NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
     ngx_conf_set_flag_slot, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_mesi_loc_conf_t, enable_mesi), NULL},

    {ngx_string("mesi_cache_backend"), NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_mesi_loc_conf_t, cache_backend), NULL},

    {ngx_string("mesi_cache_size"), NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_num_slot, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_mesi_loc_conf_t, cache_size), NULL},

    {ngx_string("mesi_cache_ttl"), NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_num_slot, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_mesi_loc_conf_t, cache_ttl), NULL},

    {ngx_string("mesi_cache_memcached_servers"), NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_mesi_loc_conf_t, cache_memcached_servers), NULL},

    {ngx_string("mesi_cache_redis_addr"), NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_mesi_loc_conf_t, cache_redis_addr), NULL},

    {ngx_string("mesi_cache_redis_password"), NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_mesi_loc_conf_t, cache_redis_password), NULL},

    {ngx_string("mesi_cache_redis_db"), NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot, NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_mesi_loc_conf_t, cache_redis_db), NULL},

    {ngx_string("mesi_block_private_ips"), NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
     ngx_conf_set_flag_slot, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_mesi_loc_conf_t, block_private_ips), NULL},

    {ngx_string("mesi_allowed_hosts"), NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_mesi_loc_conf_t, allowed_hosts), NULL},

    {ngx_string("mesi_allow_private_ips_for_allowed"), NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
     ngx_conf_set_flag_slot, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_mesi_loc_conf_t, allow_private_ips_for_allowed), NULL},

    {ngx_string("mesi_cache_key_template"), NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_mesi_loc_conf_t, cache_key_template), NULL},

    ngx_null_command};

static ngx_http_module_t ngx_http_html_head_filter_module_ctx = {
    NULL,                           /* preconfiguration */
    ngx_http_html_head_filter_init, /* postconfiguration */
    NULL,                           /* create main configuration */
    NULL,                           /* init main configuration */
    NULL,                           /* create server configuration */
    NULL,                           /* merge server configuration */
    ngx_http_mesi_create_loc_conf,  /* create location configuration */
    ngx_http_mesi_merge_loc_conf    /* merge location configuration */
};

ngx_module_t ngx_http_mesi_module = {
    NGX_MODULE_V1,
    &ngx_http_html_head_filter_module_ctx, /* module context */
    ngx_http_mesi_commands,                /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    ngx_http_mesi_thread_init,             /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    ngx_http_mesi_thread_exit,             /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING};

static ngx_int_t ngx_http_html_mesi_head_filter(ngx_http_request_t *r) {
  ngx_http_mesi_loc_conf_t *lcf =
      ngx_http_get_module_loc_conf(r, ngx_http_mesi_module);
  if (!lcf->enable_mesi) {
    return ngx_http_next_header_filter(r);
  }

  ngx_http_html_head_filter_ctx_t *ctx;
  ngx_table_elt_t *h;

  if (r->header_only || r->headers_out.content_length_n == 0) {
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "[mESI head filter]: header only, invalid content length");

    return ngx_http_next_header_filter(r);
  }

  if (ngx_test_content_compression(r) == 1) {
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "[mESI head filter]: compression enabled");
    return ngx_http_next_header_filter(r);
  }

  if (ngx_test_is_html(r) == 0) {
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "[mESI head filter]: content type not html");
    return ngx_http_next_header_filter(r);
  }

  if (r->headers_out.status > NGX_HTTP_BAD_REQUEST) {
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "[mESI head filter]: error status code");
    return ngx_http_next_header_filter(r);
  }

  if (lcf->allowed_hosts.len > 0 && EsiParseWithConfig == NULL) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "mesi: ParseWithConfig unavailable in libgomesi — "
                  "mesi_allowed_hosts cannot be enforced; returning HTTP 500 "
                  "(fail closed)");
    r->headers_out.status = NGX_HTTP_INTERNAL_SERVER_ERROR;
    return ngx_http_next_header_filter(r);
  }

  h = ngx_list_push(&r->headers_out.headers);
  if (h == NULL) {
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "[mESI head filter]: failed to add ");
    return ngx_http_next_header_filter(r);
  }

  h->hash = 1;
  ngx_str_set(&h->key, "Surrogate-Capability");
  ngx_str_set(&h->value, "ESI/1.0");

  ctx = ngx_http_get_module_ctx(r, ngx_http_mesi_module);
  if (ctx == NULL) {
    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_html_head_filter_ctx_t));
    if (ctx == NULL) {
      return NGX_ERROR;
    }
    ctx->accumulated.len = 0;
    ctx->accumulated.data = NULL;
    ctx->done = 0;
    ngx_http_set_ctx(r, ctx, ngx_http_mesi_module);
  }

  if (r == r->main) { /* Main request */

    ngx_http_clear_content_length(r);
    ngx_http_weak_etag(r);
  }

  return ngx_http_next_header_filter(r);
}

static ngx_int_t ngx_http_html_mesi_body_filter(ngx_http_request_t *r,
                                                ngx_chain_t *in) {
  ngx_http_mesi_loc_conf_t *lcf =
      ngx_http_get_module_loc_conf(r, ngx_http_mesi_module);

  if (!lcf->enable_mesi) {
    return ngx_http_next_body_filter(r, in);
  }

  ngx_http_html_head_filter_ctx_t *ctx;
  ctx = ngx_http_get_module_ctx(r, ngx_http_mesi_module);
  if (ctx == NULL || go_module == NULL) {
    return ngx_http_next_body_filter(r, in);
  }

  ngx_chain_t *cl;
  ngx_buf_t *buf;

  for (cl = in; cl; cl = cl->next) {
    buf = cl->buf;
    if (ngx_buf_size(buf) > 0 && !ctx->done) {
      size_t old_len = ctx->accumulated.len;
      size_t new_len = old_len + ngx_buf_size(buf);

      u_char *new_data = ngx_palloc(r->pool, new_len);
      if (new_data == NULL) {
        return NGX_ERROR;
      }

      if (ctx->accumulated.data) {
        ngx_memcpy(new_data, ctx->accumulated.data, old_len);
      }
      ngx_memcpy(new_data + old_len, buf->pos, ngx_buf_size(buf));

      ctx->accumulated.data = new_data;
      ctx->accumulated.len = new_len;
    }

    if (buf->last_buf && !ctx->done) {
      ctx->done = 1;
      ngx_str_t parsed = parse(ctx->accumulated, r);

      ngx_chain_t *out = ngx_alloc_chain_link(r->pool);
      if (out == NULL) {
        return NGX_ERROR;
      }

      ngx_buf_t *b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
      if (b == NULL) {
        return NGX_ERROR;
      }

      r->headers_out.content_length_n = parsed.len;

      b->pos = parsed.data;
      b->last = parsed.data + parsed.len;
      b->memory = 1;
      b->last_buf = 1;

      out->buf = b;
      out->next = NULL;

      return ngx_http_next_body_filter(r, out);
    }
  }

  return NGX_OK;
}

static char *ngx_str_to_cstr(ngx_str_t *input, ngx_pool_t *pool);
static size_t ngx_http_mesi_unicode_space(const u_char *p, size_t len);
static char *build_memcached_config_json(ngx_http_mesi_loc_conf_t *lcf, ngx_pool_t *pool);
static char *build_redis_config_json(ngx_http_mesi_loc_conf_t *lcf, ngx_pool_t *pool);
static char *build_request_ctx_json(ngx_http_request_t *r, ngx_str_t *template,
                                    ngx_pool_t *pool);
static ngx_int_t ngx_http_mesi_contains(ngx_str_t *haystack, const u_char *needle);
static size_t mesi_json_escaped_len(const u_char *s, size_t len);
static void mesi_json_write_escaped(u_char **w, const u_char *s, size_t len);
static void mesi_json_append_str(u_char **w, const u_char *s, size_t len);

// build_memcached_config_json constructs a JSON blob for
// libgomesi.InitCacheWithConfig("memcached", ...). The JSON is
// {"servers":["host:port","host:port",...]}.
// When no servers are configured, returns {"servers":[]} so libgomesi
// produces a deterministic "servers required" error instead of silently
// defaulting to localhost:11211.
static char *build_memcached_config_json(ngx_http_mesi_loc_conf_t *lcf, ngx_pool_t *pool) {
    if (lcf->cache_memcached_servers.len == 0) {
        char *empty = ngx_palloc(pool, sizeof("{\"servers\":[]}"));
        if (empty == NULL) return NULL;
        ngx_memcpy(empty, "{\"servers\":[]}", sizeof("{\"servers\":[]}"));
        return empty;
    }

    // Copy the string so we can tokenise it.
    char *servers = ngx_str_to_cstr(&lcf->cache_memcached_servers, pool);
    if (servers == NULL) return NULL;

    // First pass: count tokens.
    int ntok = 0;
    int in_token = 0;
    for (char *p = servers; *p; p++) {
        if (*p == ' ') {
            in_token = 0;
        } else if (!in_token) {
            in_token = 1;
            ntok++;
        }
    }

    // Second pass: measure total JSON size.
    // Prefix: {"servers":[  (12 bytes)
    // Each token: "escaped",  (worst case: tokenlen*2 + 3)
    // Suffix: ]}  (2 bytes) + NUL (1 byte)
    size_t total = 12 + 2 + 1;  // prefix + ]} + NUL
    if (ntok > 1) total += (size_t)(ntok - 1);  // commas between tokens

    // Restore pointer for second pass.
    char *q = servers;
    int ti;
    for (ti = 0; ti < ntok; ti++) {
        // Skip leading spaces.
        while (*q == ' ') q++;
        char *start = q;
        while (*q && *q != ' ') q++;
        // Measure worst-case escaped length.
        size_t tlen = (size_t)(q - start);
        total += tlen * 2 + 2;  // worst-case escaped w/ quotes
    }

    char *buf = ngx_palloc(pool, total);
    if (buf == NULL) return NULL;

    char *w = buf;
    memcpy(w, "{\"servers\":[", 12); w += 12;

    // Reset q for third pass (write).
    q = servers;
    for (ti = 0; ti < ntok; ti++) {
        while (*q == ' ') q++;
        char *start = q;
        while (*q && *q != ' ') q++;
        if (ti > 0) *w++ = ',';
        *w++ = '"';
        for (char *r = start; r < q; r++) {
            if (*r == '"' || *r == '\\') *w++ = '\\';
            *w++ = *r;
        }
        *w++ = '"';
    }

    *w++ = ']';
    *w++ = '}';
    *w = '\0';
    return buf;
}

// build_redis_config_json constructs a JSON blob for
// libgomesi.InitCacheWithConfig("redis", ...). The JSON is
// {"redisAddr":"host:port","redisPassword":"…","redisDB":N}.
// When addr is empty, defaults to "localhost:6379" (libgomesi default).
static char *build_redis_config_json(ngx_http_mesi_loc_conf_t *lcf, ngx_pool_t *pool) {
    char *addr = lcf->cache_redis_addr.len > 0
        ? ngx_str_to_cstr(&lcf->cache_redis_addr, pool)
        : "localhost:6379";
    char *password = lcf->cache_redis_password.len > 0
        ? ngx_str_to_cstr(&lcf->cache_redis_password, pool)
        : "";

    // Measure: {"redisAddr":"...","redisPassword":"...","redisDB":N}
    // addr and password are escaped (worst case: double the length).
    size_t addr_len = ngx_strlen(addr);
    size_t pwd_len = ngx_strlen(password);
    size_t escaped_addr_len = addr_len * 2;
    size_t escaped_pwd_len = pwd_len * 2;

    // Fixed overhead (excluding escaped addr/pwd):
    //   {"redisAddr":"  = 14
    //   ","redisPassword":" = 19
    //   ","redisDB":  = 12
    //   <max 2 digits for 0..15> = 2
    //   } = 1
    //   NUL = 1
    // Total = 14 + 19 + 12 + 2 + 1 + 1 = 49
    size_t total = 49 + escaped_addr_len + escaped_pwd_len;

    char *buf = ngx_palloc(pool, total);
    if (buf == NULL) return NULL;

    char *w = buf;
    memcpy(w, "{\"redisAddr\":\"", 14); w += 14;

    // Escape addr
    for (char *r = addr; *r; r++) {
        if (*r == '"' || *r == '\\') *w++ = '\\';
        *w++ = *r;
    }

    memcpy(w, "\",\"redisPassword\":\"", 19); w += 19;

    // Escape password
    for (char *r = password; *r; r++) {
        if (*r == '"' || *r == '\\') *w++ = '\\';
        *w++ = *r;
    }

    // Append redisDB
    ngx_int_t db = lcf->cache_redis_db;
    if (db < 0) db = 0;
    int len = snprintf(w, total - (size_t)(w - buf), "\",\"redisDB\":%d}", (int)db);
    if (len < 0) return NULL;
    w += len;
    *w = '\0';

    return buf;
}

static char *ngx_str_to_cstr(ngx_str_t *input, ngx_pool_t *pool) {
  char *cstr = ngx_palloc(pool, input->len + 1);
  if (cstr == NULL) {
    return NULL;
  }
  ngx_memcpy(cstr, input->data, input->len);
  cstr[input->len] = '\0';
  return cstr;
}

// JSON escaping for the request context — mirrors the Apache
// (mod_mesi.c json_escape_append) and php-ext (mesi_json_append_escape)
// helpers so every C platform serialises the context identically:
// '"' and '\' are backslash-escaped, control bytes < 0x20 become
// \u00XX. Bytes >= 0x20 (including UTF-8 sequences and DEL) pass through
// verbatim — Go's encoding/json accepts them.
static size_t mesi_json_escaped_len(const u_char *s, size_t len) {
  size_t n = 0;
  for (size_t i = 0; i < len; i++) {
    if (s[i] == '"' || s[i] == '\\') {
      n += 2;
    } else if (s[i] < 0x20) {
      n += 6;
    } else {
      n++;
    }
  }
  return n;
}

static void mesi_json_write_escaped(u_char **w, const u_char *s, size_t len) {
  static const u_char hex[] = "0123456789abcdef";
  for (size_t i = 0; i < len; i++) {
    if (s[i] == '"' || s[i] == '\\') {
      *(*w)++ = '\\';
      *(*w)++ = s[i];
    } else if (s[i] < 0x20) {
      *(*w)++ = '\\';
      *(*w)++ = 'u';
      *(*w)++ = '0';
      *(*w)++ = '0';
      *(*w)++ = hex[(s[i] >> 4) & 0xf];
      *(*w)++ = hex[s[i] & 0xf];
    } else {
      *(*w)++ = s[i];
    }
  }
}

// Append a complete JSON string literal (quotes + escaped body).
static void mesi_json_append_str(u_char **w, const u_char *s, size_t len) {
  *(*w)++ = '"';
  mesi_json_write_escaped(w, s, len);
  *(*w)++ = '"';
}

// Bounded substring search for non-NUL-terminated ngx_str_t data.
// ngx_strnstr() delegates to ngx_strncmp(), which may read past the len
// boundary when a partial match starts near the end; this helper never
// touches bytes outside [data, data + len).
static ngx_int_t ngx_http_mesi_contains(ngx_str_t *haystack,
                                        const u_char *needle) {
  size_t nlen = ngx_strlen(needle);
  size_t i;
  if (haystack->len < nlen) {
    return 0;
  }
  for (i = 0; i + nlen <= haystack->len; i++) {
    if (ngx_memcmp(haystack->data + i, needle, nlen) == 0) {
      return 1;
    }
  }
  return 0;
}

// build_request_ctx_json serialises the incoming request's headers and
// cookies into the shared request-context format consumed by libgomesi
// ParseWithConfigCtx / mesi.BuildCacheKey:
//   {"headers":{"Name":"value"},"cookies":[{"name":"n","value":"v"}]}
// Header lookup on the Go side is case-insensitive (BuildCacheKey tries
// canonical/lower/upper forms), so nginx's lowercased header names work
// with any placeholder capitalisation. The Cookie header is excluded from
// the headers map and its value is tokenised into the cookies array —
// passing it in both would duplicate cookies on the Go side
// (http.Request.AddCookie appends to the same Header["Cookie"] entry).
//
// When the template contains no ${header:…}/${cookie:…} placeholder the
// context cannot influence the key, so "" is returned and libgomesi uses
// a dummy request — the per-request JSON build is skipped entirely
// (same optimisation as Apache's build_request_ctx_json).
//
// Two passes over the header list (measure, then write) keep the
// allocation exact: nginx pools have no realloc, so the Apache
// grow-and-copy pattern would leak pool memory on every growth.
static char *build_request_ctx_json(ngx_http_request_t *r, ngx_str_t *template,
                                    ngx_pool_t *pool) {
  if (template == NULL || template->len == 0) {
    return "";
  }
  int needs_ctx = ngx_http_mesi_contains(template, (u_char *)"${header:") ||
                  ngx_http_mesi_contains(template, (u_char *)"${cookie:");
  if (!needs_ctx) {
    return "";
  }

  // Pass 1: measure the exact JSON size.
  //   {"headers":{                       12 bytes
  //   per header:  "k":"v"                5 fixed bytes (4 quotes + ':')
  //                                      (+1 comma when not first)
  //   },"cookies":[                      13 bytes
  //   per cookie:  {"name":"n","value":"v"}
  //                                      22 fixed bytes: '{"name":"'
  //                                      (9, incl. the opening name
  //                                      quote) + '","value":"' (11,
  //                                      incl. both quote pairs around
  //                                      the comma+key) + closing value
  //                                      quote (1) + '}' (1)
  //                                      (+1 comma when not first)
  //   ]}                                 2 bytes
  //   + NUL                             1 byte
  size_t total = 12 + 13 + 2 + 1;
  ngx_uint_t n_headers = 0, n_cookies = 0;

  ngx_list_part_t *part = &r->headers_in.headers.part;
  ngx_table_elt_t *header = part->elts;
  ngx_uint_t i;
  for (i = 0; /* void */; i++) {
    if (i >= part->nelts) {
      if (part->next == NULL) {
        break;
      }
      part = part->next;
      header = part->elts;
      i = 0;
    }
    if (header[i].hash == 0) {
      continue;  // skipped/hidden header entry
    }
    if (header[i].key.len == 6 &&
        ngx_strncasecmp(header[i].key.data, (u_char *)"cookie", 6) == 0) {
      // Cookie headers are tokenised below (all of them).
      const u_char *c = header[i].value.data;
      size_t clen = header[i].value.len;
      while (clen > 0) {
        while (clen > 0 && (*c == ' ' || *c == ';' || *c == '\t')) {
          c++;
          clen--;
        }
        if (clen == 0) {
          break;
        }
        const u_char *name_start = c;
        size_t name_len = 0;
        while (clen > 0 && *c != '=' && *c != ';') {
          c++;
          clen--;
          name_len++;
        }
        if (clen == 0 || *c != '=') {
          // No '=': not a name=value pair — skip to the next ';'.
          while (clen > 0 && *c != ';') {
            c++;
            clen--;
          }
          continue;
        }
        clen--;
        c++;
        const u_char *val_start = c;
        size_t val_len = 0;
        while (clen > 0 && *c != ';') {
          c++;
          clen--;
          val_len++;
        }
        while (name_len > 0 &&
               (name_start[name_len - 1] == ' ' || name_start[name_len - 1] == '\t')) {
          name_len--;
        }
        while (name_len > 0 && (*name_start == ' ' || *name_start == '\t')) {
          name_start++;
          name_len--;
        }
        while (val_len > 0 &&
               (val_start[val_len - 1] == ' ' || val_start[val_len - 1] == '\t')) {
          val_len--;
        }
        while (val_len > 0 && (*val_start == ' ' || *val_start == '\t')) {
          val_start++;
          val_len--;
        }
        if (name_len == 0) {
          continue;
        }
        n_cookies++;
        // 22 fixed bytes per cookie entry (see the Pass 1 comment).
        total += 22 + mesi_json_escaped_len(name_start, name_len) +
                 mesi_json_escaped_len(val_start, val_len);
        if (n_cookies > 1) {
          total++;
        }
      }
      continue;
    }
    n_headers++;
    // 5 fixed bytes per header entry: '"' key '"' ':' '"' value '"'
    // (two JSON string literals = 4 quotes, plus the ':').
    total += 5 + mesi_json_escaped_len(header[i].key.data, header[i].key.len) +
             mesi_json_escaped_len(header[i].value.data, header[i].value.len);
    if (n_headers > 1) {
      total++;
    }
  }

  u_char *buf = ngx_palloc(pool, total);
  if (buf == NULL) {
    return NULL;
  }
  u_char *w = buf;

  // Pass 2: write.
  ngx_memcpy(w, "{\"headers\":{", 12);
  w += 12;

  n_headers = 0;
  part = &r->headers_in.headers.part;
  header = part->elts;
  for (i = 0; /* void */; i++) {
    if (i >= part->nelts) {
      if (part->next == NULL) {
        break;
      }
      part = part->next;
      header = part->elts;
      i = 0;
    }
    if (header[i].hash == 0) {
      continue;
    }
    if (header[i].key.len == 6 &&
        ngx_strncasecmp(header[i].key.data, (u_char *)"cookie", 6) == 0) {
      continue;  // serialised in the cookies array below
    }
    if (n_headers > 0) {
      *w++ = ',';
    }
    n_headers++;
    mesi_json_append_str(&w, header[i].key.data, header[i].key.len);
    *w++ = ':';
    mesi_json_append_str(&w, header[i].value.data, header[i].value.len);
  }

  ngx_memcpy(w, "},\"cookies\":[", 13);
  w += 13;

  n_cookies = 0;
  part = &r->headers_in.headers.part;
  header = part->elts;
  for (i = 0; /* void */; i++) {
    if (i >= part->nelts) {
      if (part->next == NULL) {
        break;
      }
      part = part->next;
      header = part->elts;
      i = 0;
    }
    if (header[i].hash == 0) {
      continue;
    }
    if (!(header[i].key.len == 6 &&
          ngx_strncasecmp(header[i].key.data, (u_char *)"cookie", 6) == 0)) {
      continue;
    }
    const u_char *c = header[i].value.data;
    size_t clen = header[i].value.len;
    while (clen > 0) {
      while (clen > 0 && (*c == ' ' || *c == ';' || *c == '\t')) {
        c++;
        clen--;
      }
      if (clen == 0) {
        break;
      }
      const u_char *name_start = c;
      size_t name_len = 0;
      while (clen > 0 && *c != '=' && *c != ';') {
        c++;
        clen--;
        name_len++;
      }
      if (clen == 0 || *c != '=') {
        while (clen > 0 && *c != ';') {
          c++;
          clen--;
        }
        continue;
      }
      clen--;
      c++;
      const u_char *val_start = c;
      size_t val_len = 0;
      while (clen > 0 && *c != ';') {
        c++;
        clen--;
        val_len++;
      }
      while (name_len > 0 &&
             (name_start[name_len - 1] == ' ' || name_start[name_len - 1] == '\t')) {
        name_len--;
      }
      while (name_len > 0 && (*name_start == ' ' || *name_start == '\t')) {
        name_start++;
        name_len--;
      }
      while (val_len > 0 &&
             (val_start[val_len - 1] == ' ' || val_start[val_len - 1] == '\t')) {
        val_len--;
      }
      while (val_len > 0 && (*val_start == ' ' || *val_start == '\t')) {
        val_start++;
        val_len--;
      }
      if (name_len == 0) {
        continue;
      }
      if (n_cookies > 0) {
        *w++ = ',';
      }
      n_cookies++;
      ngx_memcpy(w, "{\"name\":", 8);
      w += 8;
      mesi_json_append_str(&w, name_start, name_len);
      ngx_memcpy(w, ",\"value\":", 9);
      w += 9;
      mesi_json_append_str(&w, val_start, val_len);
      *w++ = '}';
    }
  }

  *w++ = ']';
  *w++ = '}';
  *w = '\0';

  return (char *)buf;
}

// ngx_http_mesi_unicode_space returns the width in bytes of the UTF-8 rune
// starting at p when it is a Unicode whitespace rune that libgomesi's
// strings.Fields treats as a separator (Go's unicode.IsSpace), 0 otherwise.
// Covers every non-ASCII whitespace rune: U+0085, U+00A0, U+1680,
// U+2000..U+200A, U+2028, U+2029, U+202F, U+205F and U+3000. Any other
// byte — including truncated or invalid UTF-8, which Go decodes as U+FFFD
// (not a space) — forms a hostname token, so it is not whitespace here.
static size_t ngx_http_mesi_unicode_space(const u_char *p, size_t len) {
  if (len >= 2 && p[0] == 0xc2 && (p[1] == 0x85 || p[1] == 0xa0)) {
    return 2;  // U+0085 NEL, U+00A0 no-break space
  }
  if (len >= 3 && p[0] == 0xe1 && p[1] == 0x9a && p[2] == 0x80) {
    return 3;  // U+1680 ogham space mark
  }
  if (len >= 3 && p[0] == 0xe2 && p[1] == 0x80 &&
      ((p[2] >= 0x80 && p[2] <= 0x8a)  // U+2000..U+200A
       || p[2] == 0xa8                 // U+2028 line separator
       || p[2] == 0xa9                 // U+2029 paragraph separator
       || p[2] == 0xaf))               // U+202F narrow no-break space
  {
    return 3;
  }
  if (len >= 3 && p[0] == 0xe2 && p[1] == 0x81 && p[2] == 0x9f) {
    return 3;  // U+205F medium mathematical space
  }
  if (len >= 3 && p[0] == 0xe3 && p[1] == 0x80 && p[2] == 0x80) {
    return 3;  // U+3000 ideographic space
  }
  return 0;
}

static ngx_str_t parse(ngx_str_t input, ngx_http_request_t *r) {
  ngx_str_t output = {0, NULL};

  ngx_http_mesi_loc_conf_t *lcf =
      ngx_http_get_module_loc_conf(r, ngx_http_mesi_module);

  if (lcf->cache_backend.len > 0 &&
      (!cache_initialized ||
       cache_last_backend.len != lcf->cache_backend.len ||
       ngx_strncmp(cache_last_backend.data, lcf->cache_backend.data, lcf->cache_backend.len) != 0)) {
    char *backend = ngx_str_to_cstr(&lcf->cache_backend, r->pool);
    if (strcmp(backend, "memcached") == 0) {
      // For memcached we need InitCacheWithConfig with a JSON config blob.
      if (!EsiInitCacheWithConfig) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "mesi: InitCacheWithConfig not available in libgomesi");
      } else {
        char *config_json = build_memcached_config_json(lcf, r->pool);
        if (config_json == NULL) {
          ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                        "mesi: failed to build memcached config JSON");
        } else {
          int rc = EsiInitCacheWithConfig(backend, lcf->cache_size, lcf->cache_ttl, config_json);
          if (rc < 0) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "mesi: InitCacheWithConfig failed for backend '%s' (returned %d)",
                          backend, rc);
          }
        }
      }
    } else if (strcmp(backend, "redis") == 0) {
      // For redis we need InitCacheWithConfig with a JSON config blob.
      if (!EsiInitCacheWithConfig) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "mesi: InitCacheWithConfig not available in libgomesi");
      } else {
        char *config_json = build_redis_config_json(lcf, r->pool);
        if (config_json == NULL) {
          ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                        "mesi: failed to build redis config JSON");
        } else {
          int rc = EsiInitCacheWithConfig(backend, lcf->cache_size, lcf->cache_ttl, config_json);
          if (rc < 0) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "mesi: InitCacheWithConfig failed for backend '%s' (returned %d)",
                          backend, rc);
          }
        }
      }
    } else if (EsiInitCache) {
      EsiInitCache(backend, lcf->cache_size, lcf->cache_ttl);
    }
    cache_initialized = 1;
    cache_last_backend = lcf->cache_backend;
  }

  ngx_str_t scheme = r->schema;
  ngx_str_t host = r->headers_in.host->value;
  size_t len = scheme.len + sizeof("://") - 1 + host.len + sizeof("/") - 1;

  // Relative <esi:include src="..."> paths resolve against this base URL,
  // which is built from the request's Host header. When mesi_allowed_hosts
  // is set, the resolved (expanded) host is subject to the whitelist in the
  // shared core — a relative include can only fetch a host the operator
  // explicitly allowed.
  ngx_str_t base_url;
  base_url.len = len;
  base_url.data = ngx_pnalloc(r->pool, len + 1);
  if (base_url.data == NULL) {
    return output;
  }

  ngx_snprintf(base_url.data, len + 1, "%V://%V/", &scheme, &host);

  char *input_cstr = ngx_str_to_cstr(&input, r->pool);
  char *base_url_cstr = ngx_str_to_cstr(&base_url, r->pool);

  // AllowedHosts is checked by hostname before any dial; BlockPrivateIPs
  // runs at dial time. Empty string = no hostname restriction.
  char *hosts_cstr = lcf->allowed_hosts.len > 0
                         ? ngx_str_to_cstr(&lcf->allowed_hosts, r->pool)
                         : "";

  char *message = NULL;
  if (lcf->cache_key_template.len > 0 && EsiParseWithConfigCtx != NULL) {
    // ParseWithConfigCtx extends ParseWithConfigEx with the
    // cacheKeyTemplate + requestCtxJSON parameters: the shared core
    // installs a CacheKeyFunc that evaluates the template via
    // mesi.BuildCacheKey (${url}, ${header:Name} case-insensitive,
    // ${cookie:Name} case-insensitive; unknown placeholders stay
    // literal). The template travels verbatim — nginx performs no
    // ${VAR} interpolation of directive arguments (unlike Apache's
    // ap_resolve_env, no $$ escaping is needed). The request context
    // JSON is only built when the template actually references a
    // header/cookie; otherwise "" reaches libgomesi, which then uses a
    // dummy request (identical key, zero per-request overhead).
    char *template_cstr = ngx_str_to_cstr(&lcf->cache_key_template, r->pool);
    char *ctx_json = build_request_ctx_json(r, &lcf->cache_key_template, r->pool);
    if (template_cstr == NULL || ctx_json == NULL) {
      ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "mesi: failed to allocate cache key template context");
      return (ngx_str_t){0, (u_char *)""};
    }
    message = EsiParseWithConfigCtx(input_cstr, 5, base_url_cstr, hosts_cstr,
                                    lcf->block_private_ips,
                                    lcf->allow_private_ips_for_allowed,
                                    template_cstr, ctx_json);
  } else if (lcf->cache_key_template.len > 0) {
    // Fail loud, never silently wrong keys: with a stale libgomesi that
    // lacks ParseWithConfigCtx the template CANNOT be honoured, so warn
    // per request and fall back to the URL-only DefaultCacheKey path
    // below (the documented pre-template behaviour).
    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                  "mesi: mesi_cache_key_template is set but libgomesi "
                  "lacks ParseWithConfigCtx — cache key template ignored, "
                  "using URL-only cache keys");
  }

  if (message == NULL) {
    if (EsiParseWithConfigEx != NULL) {
      // ParseWithConfigEx extends ParseWithConfig with the
      // allowPrivateIPsForAllowedHosts parameter: hosts listed in
      // allowed_hosts may bypass the dial-time private-IP block (only
      // effective when block_private_ips is on AND allowed_hosts is
      // non-empty; the core grants the bypass per-host only for hosts
      // present in AllowedHosts).
      message = EsiParseWithConfigEx(input_cstr, 5, base_url_cstr, hosts_cstr,
                                     lcf->block_private_ips,
                                     lcf->allow_private_ips_for_allowed);
    } else if (EsiParseWithConfig != NULL) {
      if (lcf->allow_private_ips_for_allowed) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "mesi: mesi_allow_private_ips_for_allowed is On but "
                      "libgomesi lacks ParseWithConfigEx — private-IP bypass "
                      "for allowed hosts DISABLED, falling back to "
                      "ParseWithConfig");
      }
      // ParseWithConfig enables SSRF protection (blockPrivateIPs) and an
      // optional allowed-hosts whitelist (empty string = no restriction).
      message = EsiParseWithConfig(input_cstr, 5, base_url_cstr, hosts_cstr,
                                   lcf->block_private_ips);
    } else if (lcf->allowed_hosts.len > 0) {
      // Defensive fail-closed fallback: the header phase already refused the
      // request with HTTP 500 before any body filter ctx was created, so this
      // path should never be reached. If it ever is, return a valid empty
      // terminal response: zero length with a non-NULL data pointer, so the
      // writer never receives the NULL-pos zero-size buffer that
      // ngx_null_string would yield.
      ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "mesi: ParseWithConfig unavailable in libgomesi — "
                    "mesi_allowed_hosts cannot be enforced; failing request "
                    "(fail closed)");
      return (ngx_str_t){0, (u_char *)""};
    } else {
      ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "mesi: ParseWithConfig unavailable in libgomesi — "
                    "SSRF protection DISABLED, falling back to Parse");
      message = EsiParse(input_cstr, 5, base_url_cstr);
    }
  }

  if (message == NULL) {
    // Defensive fail-closed guard: every EsiParse*/ParseWithConfig* call
    // above is expected to return non-NULL, but libgomesi's C ABI returns
    // NULL for an out-of-range maxDepth (#414) or any other internal
    // rejection. ngx_strlen(NULL) below would dereference a NULL pointer
    // and crash the worker (SIGSEGV) instead of failing the request.
    // Fail closed the same way as the mesi_allowed_hosts stale-lib path
    // above: log at ERR and return an empty, non-NULL terminal buffer.
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "mesi: libgomesi Parse* returned NULL — failing request "
                  "(fail closed)");
    return (ngx_str_t){0, (u_char *)""};
  }

  output.len = ngx_strlen(message);
  // +1 for the NUL terminator written below — the historical allocation
  // of exactly output.len bytes made output.data[output.len] = '\0' write
  // one byte past the pool block.
  output.data = ngx_palloc(r->pool, output.len + 1);
  if (output.data == NULL) {
    free(message);
    output.len = 0;
    return output;
  }
  ngx_memcpy(output.data, message, output.len);
  output.data[output.len] = '\0';
  free(message);
  return output;
}

static ngx_int_t ngx_test_is_html(ngx_http_request_t *r) {

  if (r->headers_out.content_type.len == 0) {
    return 0;
  }

  ngx_str_t content_len = {
      .len = r->headers_out.content_type.len,
      .data = ngx_pcalloc(r->pool,
                          sizeof(u_char) * r->headers_out.content_type.len)};

  if (content_len.data == NULL) {
    return 0;
  }

  ngx_strlow(content_len.data, r->headers_out.content_type.data,
             content_len.len);

  if (ngx_strnstr(content_len.data, "text/html",
                  r->headers_out.content_type.len) != NULL) {
    return 1;
  }

  return 0;
}

static ngx_int_t ngx_test_content_compression(ngx_http_request_t *r) {
  if (r->headers_out.content_encoding == NULL ||
      r->headers_out.content_encoding->value.len == 0) {
    return 0;
  }

  return 1;
}

static ngx_int_t ngx_http_html_head_filter_init(ngx_conf_t *cf) {
  ngx_http_next_header_filter = ngx_http_top_header_filter;
  ngx_http_top_header_filter = ngx_http_html_mesi_head_filter;

  ngx_http_next_body_filter = ngx_http_top_body_filter;
  ngx_http_top_body_filter = ngx_http_html_mesi_body_filter;

  return NGX_OK;
}

static ngx_int_t ngx_http_mesi_thread_init(ngx_cycle_t *cycle) {
  char *error;
  go_module = dlopen(LIB_GOMESI_PATH, RTLD_NOW);

  if (!go_module) {
    dlerror();
    return NGX_ERROR;
  }

  EsiParse = (ParseFunc)dlsym(go_module, "Parse");

  error = dlerror();
  if (error != NULL) {
    ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                  "Error executing Parse from libgomesi: %s", error);

    return NGX_ERROR;
  }

  EsiParseWithConfig = (ParseWithConfigFunc)dlsym(go_module, "ParseWithConfig");
  if (dlerror() != NULL) {
    EsiParseWithConfig = NULL;
    ngx_log_error(NGX_LOG_WARN, cycle->log, 0,
                  "mesi: ParseWithConfig not available in libgomesi — "
                  "mesi_block_private_ips will not be enforced and a "
                  "configured mesi_allowed_hosts will fail requests "
                  "(fail closed) instead of being silently ignored");
  }

  // ParseWithConfigEx is optional: it adds the allowPrivateIPsForAllowedHosts
  // parameter. When present, the module uses it so the
  // mesi_allow_private_ips_for_allowed directive takes effect. Older
  // libgomesi builds without it fall back to ParseWithConfig (bypass
  // disabled) — the directive is then a no-op with a logged warning.
  EsiParseWithConfigEx = (ParseWithConfigExFunc)dlsym(go_module, "ParseWithConfigEx");
  if (dlerror() != NULL) {
    EsiParseWithConfigEx = NULL;
  }

  // ParseWithConfigCtx is optional: it adds the cacheKeyTemplate +
  // requestCtxJSON parameters. When present, the module uses it so the
  // mesi_cache_key_template directive takes effect. Older libgomesi
  // builds without it fall back to ParseWithConfigEx/ParseWithConfig
  // (URL-only DefaultCacheKey) — the template is then ignored with a
  // per-request warning logged in parse() (never silently wrong keys).
  EsiParseWithConfigCtx = (ParseWithConfigCtxFunc)dlsym(go_module, "ParseWithConfigCtx");
  if (dlerror() != NULL) {
    EsiParseWithConfigCtx = NULL;
  }

  EsiInitCache = (InitCacheFunc)dlsym(go_module, "InitCache");
  if (dlerror() != NULL) {
    EsiInitCache = NULL;
  }

  EsiInitCacheWithConfig = (InitCacheWithConfigFunc)dlsym(go_module, "InitCacheWithConfig");
  if (dlerror() != NULL) {
    EsiInitCacheWithConfig = NULL;
  }

  EsiFreeCache = (FreeCacheFunc)dlsym(go_module, "FreeCache");
  if (dlerror() != NULL) {
    EsiFreeCache = NULL;
  }

  return NGX_OK;
}

static void ngx_http_mesi_thread_exit(ngx_cycle_t *cycle) {
  if (EsiFreeCache) {
    EsiFreeCache();
  }
  if (go_module) {
    dlclose(go_module);
    go_module = NULL;
    cache_initialized = 0;
    cache_last_backend.len = 0;
    cache_last_backend.data = NULL;
  }
}

static void *ngx_http_mesi_create_loc_conf(ngx_conf_t *cf) {
  ngx_http_mesi_loc_conf_t *conf;
  conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_mesi_loc_conf_t));
  if (conf == NULL) {
    return NULL;
  }
  conf->enable_mesi = NGX_CONF_UNSET;
  conf->cache_size = NGX_CONF_UNSET;
  conf->cache_ttl = NGX_CONF_UNSET;
  conf->cache_redis_db = NGX_CONF_UNSET;
  conf->block_private_ips = NGX_CONF_UNSET;
  conf->allow_private_ips_for_allowed = NGX_CONF_UNSET;
  return conf;
}

static char *ngx_http_mesi_merge_loc_conf(ngx_conf_t *cf, void *parent,
                                           void *child) {
  ngx_http_mesi_loc_conf_t *prev = parent;
  ngx_http_mesi_loc_conf_t *conf = child;
  ngx_conf_merge_value(conf->enable_mesi, prev->enable_mesi, 0);
  ngx_conf_merge_str_value(conf->cache_backend, prev->cache_backend, "");
  ngx_conf_merge_value(conf->cache_size, prev->cache_size, 10000);
  ngx_conf_merge_value(conf->cache_ttl, prev->cache_ttl, 30);
  ngx_conf_merge_str_value(conf->cache_memcached_servers, prev->cache_memcached_servers, "");
  ngx_conf_merge_str_value(conf->cache_redis_addr, prev->cache_redis_addr, "");
  ngx_conf_merge_str_value(conf->cache_redis_password, prev->cache_redis_password, "");
  ngx_conf_merge_value(conf->cache_redis_db, prev->cache_redis_db, 0);
  // Default ON: nginx previously had no SSRF protection (implicit off).
  // Enabling by default is a BREAKING CHANGE — operators with intentional
  // private-IP includes must set `mesi_block_private_ips off;`.
  ngx_conf_merge_value(conf->block_private_ips, prev->block_private_ips, 1);
  // Empty (unset) = no hostname restriction (backward compatible). A child
  // that sets its own hosts always overrides the parent's list.
  ngx_conf_merge_str_value(conf->allowed_hosts, prev->allowed_hosts, "");
  // Default OFF: private IPs always blocked regardless of allowed_hosts
  // membership unless the operator explicitly opts into the bypass (the
  // same secure default as Apache's MesiAllowPrivateIPsForAllowedHosts).
  ngx_conf_merge_value(conf->allow_private_ips_for_allowed,
                       prev->allow_private_ips_for_allowed, 0);
  // Empty (unset) = URL-only DefaultCacheKey (backward compatible); an
  // explicitly empty value keeps the same meaning.
  ngx_conf_merge_str_value(conf->cache_key_template, prev->cache_key_template, "");
  if (conf->cache_key_template.len > 0) {
    // Mirror the Apache MesiCacheKeyTemplate validator: cap the length
    // (unbounded config values must not drive unbounded allocations —
    // the template is copied into a per-request C string) and reject
    // control characters and DEL, which would end up verbatim in cache
    // keys and logs. Spaces are allowed (a template may legitimately
    // use them as separators); '"' and '\' are allowed (the template
    // travels as a plain C string — only the request-context JSON is
    // escaped, never the template). nginx performs no ${VAR}
    // interpolation of directive arguments, so no Apache-style "$$"
    // escaping or mangled-template ("::"/trailing ":") checks apply —
    // the value is taken verbatim.
    if (conf->cache_key_template.len > MESI_MAX_CACHE_KEY_TEMPLATE) {
      ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                         "\"mesi_cache_key_template\" exceeds maximum length "
                         "%d (got %d)",
                         MESI_MAX_CACHE_KEY_TEMPLATE,
                         (int)conf->cache_key_template.len);
      return NGX_CONF_ERROR;
    }
    for (size_t ti = 0; ti < conf->cache_key_template.len; ti++) {
      u_char tc = conf->cache_key_template.data[ti];
      if (tc < 0x20) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"mesi_cache_key_template\" must not contain "
                           "control characters (found byte %d)", (int)tc);
        return NGX_CONF_ERROR;
      }
      if (tc == 0x7f) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"mesi_cache_key_template\" must not contain the "
                           "DEL character");
        return NGX_CONF_ERROR;
      }
    }
  }
  if (conf->allowed_hosts.len > 0) {
    // Reject whitespace-only allowlists: they would silently disable the
    // hostname restriction the operator intended to configure. libgomesi
    // splits the value with Go's strings.Fields, so the check mirrors that
    // tokenization: every byte of the ASCII whitespace set (space, tab, CR,
    // LF, VT, FF) plus every rune of the Unicode whitespace set (U+0085,
    // U+00A0, U+1680, U+2000..U+200A, U+2028, U+2029, U+202F, U+205F,
    // U+3000 — e.g. a no-break space U+00A0 encoded as bytes c2 a0) counts
    // as a separator, and a value with no hostname token at all is rejected.
    // Any other byte, including invalid UTF-8, forms a token exactly like
    // strings.Fields.
    size_t i = 0;
    while (i < conf->allowed_hosts.len) {
      u_char c = conf->allowed_hosts.data[i];
      size_t ws_width;
      if (c == ' ' || c == '\t' || c == '\r' || c == '\n' ||
          c == '\v' || c == '\f') {
        i++;
        continue;
      }
      ws_width = ngx_http_mesi_unicode_space(&conf->allowed_hosts.data[i],
                                             conf->allowed_hosts.len - i);
      if (ws_width == 0) {
        break;  // a non-whitespace rune: the value has a hostname token
      }
      i += ws_width;
    }
    if (i == conf->allowed_hosts.len) {
      ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                         "\"mesi_allowed_hosts\" must contain at least "
                         "one hostname");
      return NGX_CONF_ERROR;
    }
  }
  return NGX_CONF_OK;
}
