#include <sys/ioctl.h>
#include <sys/socket.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <signal.h>
#include <string.h>

#ifdef JSONC
	#include <json.h>
#else
	#include <json-c/json.h>
#endif

#include "lexer.h"
#include "parser.h"
#include "matcher.h" 
#include "ast.h"

// Fuzzer modes to test different aspects
#define MODE_PARSE_ONLY       0
#define MODE_TOKEN_ONLY       1  
#define MODE_PARSE_AND_MATCH  2
#define MODE_FULL_PIPELINE    3
#define MODE_JSON_PARSE       4

// Simple callback for jp_match testing
static void fuzz_match_callback(struct json_object *res, void *priv) {
    // Do nothing - we just want to exercise the matching logic
    (void)res;
    (void)priv;
}

// Test jp_parse function with various inputs
static void fuzz_jp_parse(const uint8_t *data, size_t size) {
    if (size == 0 || size > 512) return;
    
    char *expr = malloc(size + 1);
    if (!expr) return;
    
    memcpy(expr, data, size);
    expr[size] = '\0';
    
    // Test jp_parse
    struct jp_state *state = jp_parse(expr);
    if (state) {
        // Check if parsing succeeded and we have a valid path
        if (state->path && state->error_code == 0) {
            // Exercise the parsed state a bit more
            (void)state->error_pos;
            (void)state->off;
        }
        jp_free(state);
    }
    
    free(expr);
}

// Test jp_get_token function directly
static void fuzz_jp_get_token(const uint8_t *data, size_t size) {
    if (size == 0 || size > 256) return;
    
    char *input = malloc(size + 1);
    if (!input) return;
    
    memcpy(input, data, size);
    input[size] = '\0';
    
    // Create a minimal jp_state for tokenization
    struct jp_state *state = calloc(1, sizeof(*state));
    if (!state) {
        free(input);
        return;
    }
    
    // Test tokenization
    int mlen = 0;
    const char *ptr = input;
    int remaining = size;
    
    // Try to tokenize the entire input
    while (remaining > 0) {
        struct jp_opcode *op = jp_get_token(state, ptr, &mlen);
        
        if (mlen <= 0 || mlen > remaining) {
            break; // Error or end of input
        }
        
        ptr += mlen;
        remaining -= mlen;
        
        // Prevent infinite loops
        if (remaining == size) break;
    }
    
    jp_free(state);
    free(input);
}

// Test full parsing + matching pipeline
static void fuzz_parse_and_match(const uint8_t *data, size_t size) {
    if (size < 4 || size > 1024) return;
    
    // Split input: first part for JSONPath expression, second for JSON data
    size_t split_point = size / 3; // Use 1/3 for expression, 2/3 for JSON
    if (split_point == 0) split_point = 1;
    
    // Extract JSONPath expression
    char *expr = malloc(split_point + 1);
    if (!expr) return;
    
    memcpy(expr, data, split_point);
    expr[split_point] = '\0';
    
    // Extract JSON data
    size_t json_size = size - split_point;
    char *json_str = malloc(json_size + 1);
    if (!json_str) {
        free(expr);
        return;
    }
    
    memcpy(json_str, data + split_point, json_size);
    json_str[json_size] = '\0';
    
    // Test jp_parse
    struct jp_state *state = jp_parse(expr);
    if (state && state->path && state->error_code == 0) {
        // Try to parse JSON
        struct json_object *json_obj = json_tokener_parse(json_str);
        if (json_obj) {
            // Test jp_match
            struct json_object *result = jp_match(state->path, json_obj, 
                                                  fuzz_match_callback, NULL);
            (void)result; // Suppress unused variable warning
            
            json_object_put(json_obj);
        }
        jp_free(state);
    }
    
    free(expr);
    free(json_str);
}

// Test comprehensive pipeline with error injection
static void fuzz_full_pipeline(const uint8_t *data, size_t size) {
    if (size < 6 || size > 2048) return;
    
    // Use different portions of input for different purposes
    size_t expr_size = size / 4;
    size_t json_size = size / 2;
    size_t remaining = size - expr_size - json_size;
    
    if (expr_size == 0) expr_size = 1;
    if (json_size == 0) json_size = 1;
    
    char *expr = malloc(expr_size + 1);
    char *json_str = malloc(json_size + 1);
    if (!expr || !json_str) {
        free(expr);
        free(json_str);
        return;
    }
    
    memcpy(expr, data, expr_size);
    expr[expr_size] = '\0';
    
    memcpy(json_str, data + expr_size, json_size);
    json_str[json_size] = '\0';
    
    // Test parsing with various edge cases
    struct jp_state *state = jp_parse(expr);
    if (state) {
        // Even if parsing failed, exercise error handling
        if (state->error_code != 0) {
            (void)state->error_pos; // Exercise error position
        }
        
        if (state->path) {
            // Create some test JSON objects
            struct json_object *test_objects[] = {
                json_tokener_parse(json_str),
                json_object_new_object(),
                json_object_new_array(),
                json_object_new_string("test"),
                json_object_new_int(42),
                json_object_new_boolean(true),
                NULL
            };
            
            // Test matching against various JSON structures
            for (int i = 0; test_objects[i] != NULL; i++) {
                if (test_objects[i]) {
                    jp_match(state->path, test_objects[i], fuzz_match_callback, NULL);
                    json_object_put(test_objects[i]);
                }
            }
        }
        
        jp_free(state);
    }
    
    free(expr);
    free(json_str);
}

// Helper function to parse JSON chunks (mimics parse_json_chunk from main.c)
static struct json_object *
fuzz_parse_json_chunk(struct json_tokener *tok, struct json_object *array,
                      const char *buf, size_t len, enum json_tokener_error *err)
{
    struct json_object *obj = NULL;

    while (len)
    {
        obj = json_tokener_parse_ex(tok, buf, len);
        *err = json_tokener_get_error(tok);

        if (*err == json_tokener_success)
        {
            if (array)
            {
                json_object_array_add(array, obj);
            }
            else
            {
                break;
            }
        }
        else if (*err != json_tokener_continue)
        {
            break;
        }

        buf += tok->char_offset;
        len -= tok->char_offset;
    }

    return obj;
}

// Test json parsing like parse_json function from main.c but using fuzzer input
static void fuzz_parse_json(const uint8_t *data, size_t size) {
    if (size <= 1 || size > 4096) return;
    
    // Use first byte to determine array_mode
    bool array_mode = data[0] % 2;
    const uint8_t *json_data = data + 1;
    size_t json_size = size - 1;
    
    struct json_object *obj = NULL, *array = NULL;
    struct json_tokener *tok = json_tokener_new();
    enum json_tokener_error err = json_tokener_continue;
    const char *error = NULL;

    if (!tok)
    {
        return; // Out of memory
    }

    if (array_mode)
    {
        array = json_object_new_array();

        if (!array)
        {
            json_tokener_free(tok);
            return; // Out of memory
        }
    }

    const char *buf = (const char *)json_data;
    size_t remaining = json_size;
    size_t chunk_size = 256; 
    
    while (remaining > 0)
    {
        size_t current_chunk = (remaining > chunk_size) ? chunk_size : remaining;
        
        obj = fuzz_parse_json_chunk(tok, array, buf, current_chunk, &err);

        if ((err == json_tokener_success && array_mode == false) ||
            (err != json_tokener_continue && err != json_tokener_success))
            break;
            
        buf += current_chunk;
        remaining -= current_chunk;
    }

    json_tokener_free(tok);

    if (err)
    {
        if (err == json_tokener_continue)
            err = json_tokener_error_parse_eof;

        error = json_tokener_error_desc(err);
        // In fuzzing, we don't print errors, just exercise the error path
        (void)error;
    }

    // Exercise the resulting object if parsing succeeded
    struct json_object *result = array ? array : obj;
    if (result && !err)
    {
        // Exercise various JSON object operations
        (void)json_object_get_type(result);
        (void)json_object_to_json_string(result);
        
        // If it's an array, exercise array operations
        if (array)
        {
            int len = json_object_array_length(array);
            for (int i = 0; i < len && i < 10; i++) // Limit to avoid excessive processing
            {
                struct json_object *item = json_object_array_get_idx(array, i);
                if (item)
                {
                    (void)json_object_get_type(item);
                }
            }
        }
    }
    
    // Always clean up the result object to prevent memory leaks
    if (result)
    {
        json_object_put(result);
    }
}



int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) return 0;
    
    // Use first byte to determine fuzzing mode
    uint8_t mode = data[0] % 5;
    const uint8_t *fuzz_data = data + 1;
    size_t fuzz_size = size - 1;
    
    switch (mode) {
        case MODE_PARSE_ONLY:
            fuzz_jp_parse(fuzz_data, fuzz_size);
            break;
            
        case MODE_TOKEN_ONLY:
            fuzz_jp_get_token(fuzz_data, fuzz_size);
            break;
            
        case MODE_PARSE_AND_MATCH:
            fuzz_parse_and_match(fuzz_data, fuzz_size);
            break;
            
        case MODE_FULL_PIPELINE:
            fuzz_full_pipeline(fuzz_data, fuzz_size);
            break;
            
        case MODE_JSON_PARSE:
            fuzz_parse_json(fuzz_data, fuzz_size);
            break;
    }
    
    return 0;
}

// #ifndef __AFL_FUZZ_TESTCASE_LEN

// ssize_t fuzz_len;
// unsigned char fuzz_buf[1024000];

// #define __AFL_FUZZ_TESTCASE_LEN fuzz_len
// #define __AFL_FUZZ_TESTCASE_BUF fuzz_buf  
// #define __AFL_FUZZ_INIT() void sync(void);
// #define __AFL_LOOP(x) \
//     ((fuzz_len = read(0, fuzz_buf, sizeof(fuzz_buf))) > 0 ? 1 : 0)
// #define __AFL_INIT() sync()

// #endif

// __AFL_FUZZ_INIT();

// #pragma clang optimize off
// #pragma GCC optimize("O0")

// int main(int argc, char **argv)
// {
//     (void)argc; (void)argv; 
    
//     ssize_t len;
//     unsigned char *buf;

//     __AFL_INIT();
//     buf = __AFL_FUZZ_TESTCASE_BUF;
//     while (__AFL_LOOP(INT_MAX)) {
//         len = __AFL_FUZZ_TESTCASE_LEN;
//         LLVMFuzzerTestOneInput(buf, (size_t)len);
//     }
    
//     return 0;
// }