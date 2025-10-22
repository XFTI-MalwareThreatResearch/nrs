%module(package="nrs.ext") zlibnsis
%include <pybuffer.i>

%inline %{
#include "ZLIB.H"

z_stream * ZLIB_Init() {
  z_stream* s = malloc(sizeof(z_stream));
  inflateInit(s);
  return s;
}

void ZLIB_Free(z_stream* s) {
  free(s);
}

int ZLIB_Decompress(z_stream *s) {
  return inflate(s);
}

Bytef * ZLIB_GetNextOut(z_stream* s)
{
  return s->next_out;
}
unsigned int ZLIB_GetAvailIn(z_stream *s)
{
  return s->avail_in;
}

unsigned int ZLIB_GetAvailOut(z_stream *s)
{
  return s->avail_out;
}
%}

%{
#define SWIG_FILE_WITH_INIT
#include "ZLIB.h"

void ZLIB_SetInBuffer(z_stream* s, char* data, size_t data_size) {
  s->next_in = data;
  s->avail_in = data_size;
}

void ZLIB_SetOutBuffer(z_stream* s, char* data, size_t data_size) {
  s->next_out = data;
  s->avail_out = data_size;
}

%}

%pybuffer_binary(char *data, size_t data_size);
void ZLIB_SetInBuffer(z_stream* s, char* data, size_t data_size);

%pybuffer_mutable_binary(char *data, size_t data_size);
void ZLIB_SetOutBuffer(z_stream* s, char* data, size_t data_size);

%pythoncode %{
AMT_CHUNK = 0x4000
Z_OK = 0
Z_STREAM_END = 1

class ZlibException(Exception):
  pass

def decompress(data):
  try:
    state = ZLIB_Init()
    ZLIB_SetInBuffer(state, data)

    outbuf = bytearray(AMT_CHUNK)
    out = bytearray()
    amt_left = len(data)
    err = 0
    while amt_left > 0 or err != Z_STREAM_END:
      ZLIB_SetOutBuffer(state, outbuf)
      out1 = ZLIB_GetNextOut(state)
      in1 = int(ZLIB_GetAvailIn(state))
      err = ZLIB_Decompress(state)
      processed = in1 - int(ZLIB_GetAvailIn(state))
      amt_decomp = int(ZLIB_GetNextOut(state)) - int(out1)
      if err != Z_OK or err == Z_STREAM_END:
        if err == Z_STREAM_END:
          out += outbuf[:amt_decomp]
        break
      amt_left -= processed

      out += outbuf[:amt_decomp]
  finally:
    ZLIB_Free(state)
  return out
%}

