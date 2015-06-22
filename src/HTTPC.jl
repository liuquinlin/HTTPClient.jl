module HTTPC

using LibCURL
using LibCURL.Mime_ext

import Base.convert, Base.show, Base.get, Base.trace

export init, cleanup, get, connect, put, post, trace, delete, head, options
export RequestOptions, Response, ConnContext

def_rto = 0.0

##############################
# Struct definitions
##############################

type RequestOptions
  blocking::Bool
  query_params::Vector{Tuple}
  request_timeout::Float64
  max_errs::Int64
  callback::Union(Function,Bool)
  content_type::String
  headers::Vector{Tuple}
  ostream::Union(IO, String, Nothing)
  auto_content_type::Bool
  max_buff_size::Int64

  RequestOptions(; blocking=true, query_params=Array(Tuple,0), request_timeout=def_rto, max_errs=50, callback=null_cb, content_type="", headers=Array(Tuple,0), ostream=nothing, auto_content_type=true, max_buff_size=-1) =
    new(blocking, query_params, request_timeout, max_errs, callback, content_type, headers, ostream, auto_content_type, max_buff_size)
end

type Response
  body
  headers
  http_code
  total_time

  Response() = new(nothing, Dict{ASCIIString, ASCIIString}(), 0, 0.0)
end

function show(io::IO, o::Response)
  println(io, "HTTP Code   : ", o.http_code)
  println(io, "RequestTime : ", o.total_time)
  println(io, "Headers     : ")
  for (k,v) in o.headers
    println(io, "    $k : $v")
  end

  println(io, "Length of body : ", position(o.body))
end

type ReadData
  typ::Symbol
  src::Any
  str::String
  offset::Csize_t
  sz::Csize_t

  ReadData() = new(:undefined, false, "", 0, 0)
end

type StreamData
  state::Symbol
  buff::IOBuffer
  bytesRead::Integer
  errs::Integer

  StreamData() = new(:NONE, IOBuffer(), 0, 0)
end

function show(io::IO, o::StreamData)
  println(io, "State: $(o.state) | bytesRead: $(o.bytesRead) | errs: $(o.errs)")
  println(io, "Buff : $(o.buff)")
end

type ConnContext
  curl::Ptr{CURL}
  curlm::Ptr{CURL}
  url::String
  slist::Ptr{Void}
  rd::ReadData
  resp::Response
  options::RequestOptions
  close_ostream::Bool
  bytes_recd::Integer
  stream::Union(Nothing, StreamData) # used for streaming

  ConnContext(options::RequestOptions) = new(C_NULL, C_NULL, "", C_NULL, ReadData(), Response(), options, false, 0, StreamData())
end

function show(io::IO, o::ConnContext)
  println(io, "URL       : $(o.url)")
  println(io, "Curl Ptr  : $(o.curl) | MultiCurl Ptr: $(o.curlm)")
  println(io, "Bytes Recd: $(o.bytes_recd)")
  println(io, "Read Data : $(o.rd)")
  print(io, "STREAM  : \n$(o.stream)")
  print(io, "RESPONSE: \n$(o.resp)")
end

immutable CURLMsg2
  msg::CURLMSG
  easy_handle::Ptr{CURL}
  data::Ptr{Any}
end

##############################
# Callbacks
##############################

function write_cb(buff::Ptr{Uint8}, sz::Csize_t, n::Csize_t, p_ctxt::Ptr{Void})
  #    println("@write_cb")
  ctxt = unsafe_pointer_to_objref(p_ctxt)
  nbytes = sz * n
  if (ctxt.stream.state != :NONE)
    ctxt.stream.buff = IOBuffer()
    write(ctxt.stream.buff, buff, nbytes)
  else
    write(ctxt.resp.body, buff, nbytes)
  end
  ctxt.bytes_recd = ctxt.bytes_recd + nbytes
  nbytes::Csize_t
end

c_write_cb = cfunction(write_cb, Csize_t, (Ptr{Uint8}, Csize_t, Csize_t, Ptr{Void}))

function header_cb(buff::Ptr{Uint8}, sz::Csize_t, n::Csize_t, p_ctxt::Ptr{Void})
  #    println("@header_cb")
  ctxt = unsafe_pointer_to_objref(p_ctxt)
  hdrlines = split(bytestring(buff, convert(Int, sz * n)), "\r\n")

  #    println(hdrlines)
  for e in hdrlines
    m = match(r"^\s*([\w\-\_]+)\s*\:(.+)", e)
    if (m != nothing)
      ctxt.resp.headers[strip(m.captures[1])] = strip(m.captures[2])
    end
  end
  (sz*n)::Csize_t
end

c_header_cb = cfunction(header_cb, Csize_t, (Ptr{Uint8}, Csize_t, Csize_t, Ptr{Void}))


function curl_read_cb(out::Ptr{Void}, s::Csize_t, n::Csize_t, p_ctxt::Ptr{Void})
  #    println("@curl_read_cb")

  ctxt = unsafe_pointer_to_objref(p_ctxt)
  bavail::Csize_t = s * n
  breq::Csize_t = ctxt.rd.sz - ctxt.rd.offset
  b2copy = bavail > breq ? breq : bavail

  if (ctxt.rd.typ == :buffer)
    ccall(:memcpy, Ptr{Void}, (Ptr{Void}, Ptr{Void}, Uint),
          out, convert(Ptr{Uint8}, pointer(ctxt.rd.str)) + ctxt.rd.offset, b2copy)
  elseif (ctxt.rd.typ == :io)
    b_read = read(ctxt.rd.src, Uint8, b2copy)
    ccall(:memcpy, Ptr{Void}, (Ptr{Void}, Ptr{Void}, Uint), out, b_read, b2copy)
  end
  ctxt.rd.offset = ctxt.rd.offset + b2copy

  r = convert(Csize_t, b2copy)
  r::Csize_t
end

c_curl_read_cb = cfunction(curl_read_cb, Csize_t, (Ptr{Void}, Csize_t, Csize_t, Ptr{Void}))



function curl_socket_cb(curl::Ptr{Void}, s::Cint, action::Cint, p_muctxt::Ptr{Void}, sctxt::Ptr{Void})
  if action != CURL_POLL_REMOVE
    muctxt = unsafe_pointer_to_objref(p_muctxt)

    muctxt.s = s
    muctxt.chk_read = false
    muctxt.chk_write = false

    if action == CURL_POLL_IN
      muctxt.chk_read = true

    elseif action == CURL_POLL_OUT
      muctxt.chk_write = true

    elseif action == CURL_POLL_INOUT
      muctxt.chk_read = true
      muctxt.chk_write = true
    end
  end

  # NOTE: Out-of-order socket fds cause problems in the case of HTTP redirects, hence ignoring CURL_POLL_REMOVE
  ret = convert(Cint, 0)
  ret::Cint
end

c_curl_socket_cb = cfunction(curl_socket_cb, Cint, (Ptr{Void}, Cint, Cint, Ptr{Void}, Ptr{Void}))



function curl_multi_timer_cb(curlm::Ptr{Void}, timeout_ms::Clong, p_muctxt::Ptr{Void})
  muctxt = unsafe_pointer_to_objref(p_muctxt)
  muctxt.timeout = timeout_ms / 1000.0

  #    println("Requested timeout value : " * string(muctxt.timeout))

  ret = convert(Cint, 0)
  ret::Cint
end

c_curl_multi_timer_cb = cfunction(curl_multi_timer_cb, Cint, (Ptr{Void}, Clong, Ptr{Void}))




##############################
# Utility functions
##############################

macro ce_curl (f, args...)
  quote
    cc = CURLE_OK
    cc = $(esc(f))(ctxt.curl, $(args...))

    if(cc != CURLE_OK)
      error (string($f) * "() failed: " * bytestring(curl_easy_strerror(cc)))
    end
  end
end

macro ce_curlm (f, args...)
  quote
    cc = CURLM_OK
    cc = $(esc(f))(curlm, $(args...))

    if(cc != CURLM_OK)
      error (string($f) * "() failed: " * bytestring(curl_multi_strerror(cc)))
    end
  end
end


null_cb(curl) = return nothing

function set_opt_blocking(options::RequestOptions)
  o2 = deepcopy(options)
  o2.blocking = true
  return o2
end

function get_ct_from_ext(filename)
  fparts = split(basename(filename), ".")
  if (length(fparts) > 1)
    if haskey(MimeExt, fparts[end]) return MimeExt[fparts[end]] end
  end
  return false
end


function setup_easy_handle(url, options::RequestOptions)
  ctxt = ConnContext(options)

  curl = curl_easy_init()
  if (curl == C_NULL) throw("curl_easy_init() failed") end

  ctxt.curl = curl

  @ce_curl curl_easy_setopt CURLOPT_FOLLOWLOCATION 1

  @ce_curl curl_easy_setopt CURLOPT_MAXREDIRS 5

  if length(options.query_params) > 0
    qp = urlencode_query_params(curl, options.query_params)
    url = url * "?" * qp
  end

  ctxt.url = url

  @ce_curl curl_easy_setopt CURLOPT_URL url
  @ce_curl curl_easy_setopt CURLOPT_WRITEFUNCTION c_write_cb

  p_ctxt = pointer_from_objref(ctxt)

  @ce_curl curl_easy_setopt CURLOPT_WRITEDATA p_ctxt

  @ce_curl curl_easy_setopt CURLOPT_HEADERFUNCTION c_header_cb
  @ce_curl curl_easy_setopt CURLOPT_HEADERDATA p_ctxt

  ### INSECURE, allow https connections; only necessary on Windows due
  ### to lacking a default CA bundle... very sad
  @ce_curl curl_easy_setopt CURLOPT_SSL_VERIFYPEER 0
  @ce_curl curl_easy_setopt CURLOPT_VERBOSE 1
  @ce_curl curl_easy_setopt CURLOPT_NOSIGNAL # for threading

  if options.content_type != ""
    ct = "Content-Type: " * options.content_type
    ctxt.slist = curl_slist_append (ctxt.slist, ct)
  else
    # Disable libCURL automatically setting the content type
    ctxt.slist = curl_slist_append (ctxt.slist, "Content-Type:")
  end


  for hdr in options.headers
    hdr_str = hdr[1] * ":" * hdr[2]
    ctxt.slist = curl_slist_append (ctxt.slist, hdr_str)
  end

  # Disabling the Expect header since some webservers don't handle this properly
  ctxt.slist = curl_slist_append (ctxt.slist, "Expect:")
  @ce_curl curl_easy_setopt CURLOPT_HTTPHEADER ctxt.slist

  if isa(options.ostream, String)
    ctxt.resp.body = open(options.ostream, "w+")
    ctxt.close_ostream = true
  elseif isa(options.ostream, IO)
    ctxt.resp.body = options.ostream
  else
    ctxt.resp.body = IOBuffer()
  end

  ctxt
end

function cleanup_context(ctxt::Union(ConnContext,Bool))
  if isa(ctxt, ConnContext)
    if (ctxt.slist != C_NULL)
      curl_slist_free_all(ctxt.slist)
    end

    if (ctxt.curl != C_NULL)
      if (ctxt.curlm != C_NULL)
        curl_multi_remove_handle(ctxt.curlm, ctxt.curl)
      end
      curl_easy_cleanup(ctxt.curl)
      if (ctxt.curlm != C_NULL)
        curl_multi_cleanup(ctxt.curlm)
      end
    end

    if ctxt.close_ostream
      close(ctxt.resp.body)
      ctxt.resp.body = nothing
      ctxt.close_ostream = false
    end
  end
end

function process_response(ctxt)
  http_code = Array(Clong,1)
  @ce_curl curl_easy_getinfo CURLINFO_RESPONSE_CODE http_code

  total_time = Array(Cdouble,1)
  @ce_curl curl_easy_getinfo CURLINFO_TOTAL_TIME total_time

  ctxt.resp.http_code = http_code[1]
  ctxt.resp.total_time = total_time[1]
end


##############################
# Library initializations
##############################

init() = curl_global_init(CURL_GLOBAL_ALL)
cleanup() = curl_global_cleanup()

##############################
# CONNECT / DISCONNECT / ISDONE
##############################

# returns a context connected to the specified url (used for streaming)
function connect(url::String, options::RequestOptions=RequestOptions())
  #create easy handle
  ctxt = setup_easy_handle(url, options)
  curl = ctxt.curl

  const MAX_BUFFER_SIZE = 16384 # 16KiB
  if (options.max_buff_size != -1)
    if (options.max_buff_size > MAX_BUFFER_SIZE|| options.max_buff_size < 0)
      throw("the max buffer size must be positive and less than or equal to 16KiB")
    else
      # sets CURL_MAX_WRITE_SIZE if specified
      @ce_curl curl_easy_setopt CURLOPT_BUFFERSIZE options.max_buff_size
    end
  end

  # create multi handle
  curlm = curl_multi_init()
  if (curlm == C_NULL) throw("curl_multi_init() failed") end
  curl_multi_add_handle(curlm, curl)
  ctxt.curlm = curlm
  ctxt.stream.state = :CONNECTED

  return ctxt
end

function disconnect(ctxt::ConnContext)
  if ctxt.stream.state == :NONE
    throw("Error: Failed to disconnect ctxt because it isn't connected to begin with!")
  end
  cleanup_context(ctxt)
  ctxt.stream.state = :NONE
end

function isDone(ctxt::ConnContext)
  return (ctxt.stream.state == :DONE)
end

# check if a context is open / available for streaming (connected to)
function isOpen(ctxt::ConnContext)
  return (ctxt.stream.state != :NONE)
end

##############################
# GET
##############################

function get(url::String, options::RequestOptions=RequestOptions())
  if (options.blocking)
    ctxt = false
    try
      ctxt = setup_easy_handle(url, options)

      @ce_curl curl_easy_setopt CURLOPT_HTTPGET 1

      return exec_as_multi(ctxt)
    finally
      cleanup_context(ctxt)
    end
  else
    return remotecall(myid(), get, url, set_opt_blocking(options))
  end
end

# pass in a context to allow streaming; blocking
function get(ctxt::ConnContext, numBytes::Int64, options::RequestOptions=RequestOptions())
  curl = ctxt.curl
  @ce_curl curl_easy_setopt CURLOPT_HTTPGET 1

  ctxt.options.request_timeout = options.request_timeout
  ctxt.options.max_errs = options.max_errs

  bytes = exec_as_stream(ctxt, numBytes) # byte array of bytes read
  ctxt.resp = Response()
  ctxt.resp.body = IOBuffer(length(bytes)) # data stored in IOBuffer
  write(ctxt.resp.body, bytes)
  return ctxt.resp
end

#
function get(ctxt::ConnContext, options::RequestOptions=RequestOptions())
  curl = ctxt.curl
  @ce_curl curl_easy_setopt CURLOPT_HTTPGET 1

  ctxt.options.request_timeout = options.request_timeout
  ctxt.options.max_errs = options.max_errs

  return exec_as_read(ctxt)
end

# TODO: exec_as_multi, exec_as_stream, exec_as_read are all very similar, maybe try
# to refactor to consolidate the code?

##############################
# POST & PUT
##############################

function post (url::String, data, options::RequestOptions=RequestOptions())
  if (options.blocking)
    return put_post(url, data, :post, options)
  else
    return remotecall(myid(), post, url, data, set_opt_blocking(options))
  end
end

function put (url::String, data, options::RequestOptions=RequestOptions())
  if (options.blocking)
    return put_post(url, data, :put, options)
  else
    return remotecall(myid(), put, url, data, set_opt_blocking(options))
  end
end

function put_post(url::String, data, putorpost::Symbol, options::RequestOptions)
  rd::ReadData = ReadData()

  if isa(data, String)
    rd.typ = :buffer
    rd.src = false
    rd.str = data
    rd.sz = length(data)

  elseif isa(data, Dict) || (isa(data, Vector) && issubtype(eltype(data), Tuple))
    arr_data = isa(data, Dict) ? collect(data) : data
    rd.str = urlencode_query_params(arr_data)  # Not very optimal since it creates another curl handle, but it is clean...
    rd.sz = length(rd.str)
    rd.typ = :buffer
    rd.src = arr_data
    if ((options.content_type == "") && (options.auto_content_type))
      options.content_type = "application/x-www-form-urlencoded"
    end

  elseif isa(data, IO)
    rd.typ = :io
    rd.src = data
    seekend(data)
    rd.sz = position(data)
    seekstart(data)
    if ((options.content_type == "") && (options.auto_content_type))
      options.content_type = "application/octet-stream"
    end

  elseif isa(data, Tuple)
    (typsym, filename) = data
    if (typsym != :file) error ("Unsupported data datatype") end

    rd.typ = :io
    rd.src = open(filename)
    rd.sz = filesize(filename)

    try
      if ((options.content_type == "") && (options.auto_content_type))
        options.content_type = get_ct_from_ext(filename)
      end
      return _put_post(url, putorpost, options, rd)
    finally
      close(rd.src)
    end

  else
    error ("Unsupported data datatype")
  end

  return _put_post(url, putorpost, options, rd)
end




function _put_post(url::String, putorpost::Symbol, options::RequestOptions, rd::ReadData)
  ctxt = false
  try
    ctxt = setup_easy_handle(url, options)
    ctxt.rd = rd

    if (putorpost == :post)
      @ce_curl curl_easy_setopt CURLOPT_POST 1
      @ce_curl curl_easy_setopt CURLOPT_POSTFIELDSIZE rd.sz
    elseif (putorpost == :put)
      @ce_curl curl_easy_setopt CURLOPT_UPLOAD 1
      @ce_curl curl_easy_setopt CURLOPT_INFILESIZE rd.sz
    end

    if (rd.typ == :io) || (putorpost == :put)
      p_ctxt = pointer_from_objref(ctxt)
      @ce_curl curl_easy_setopt CURLOPT_READDATA p_ctxt

      @ce_curl curl_easy_setopt CURLOPT_READFUNCTION c_curl_read_cb
    else
      ppostdata = pointer(rd.str)
      @ce_curl curl_easy_setopt CURLOPT_COPYPOSTFIELDS ppostdata
    end

    return exec_as_multi(ctxt)
  finally
    cleanup_context(ctxt)
  end
end



##############################
# HEAD, DELETE and TRACE
##############################
function head(url::String, options::RequestOptions=RequestOptions())
  if (options.blocking)
    ctxt = false
    try
      ctxt = setup_easy_handle(url, options)

      @ce_curl curl_easy_setopt CURLOPT_NOBODY 1

      return exec_as_multi(ctxt)
    finally
      cleanup_context(ctxt)
    end
  else
    return remotecall(myid(), head, url, set_opt_blocking(options))
  end

end

delete(url::String, options::RequestOptions=RequestOptions()) = custom(url, "DELETE", options)
trace(url::String, options::RequestOptions=RequestOptions()) = custom(url, "TRACE", options)
options(url::String, options::RequestOptions=RequestOptions()) = custom(url, "OPTIONS", options)


for f in (:get, :head, :delete, :trace, :options)
  @eval $(f)(url::String; kwargs...) = $(f)(url, RequestOptions(; kwargs...))
end

# put(url::String, data::String; kwargs...) = put(url, data, options=RequestOptions(; kwargs...))
# post(url::String, data::String; kwargs...) = post(url, data, options=RequestOptions(; kwargs...))


for f in (:put, :post)
  @eval $(f)(url::String, data::String; kwargs...) = $(f)(url, data, RequestOptions(; kwargs...))
end


function custom(url::String, verb::String, options::RequestOptions)
  if (options.blocking)
    ctxt = false
    try
      ctxt = setup_easy_handle(url, options)

      @ce_curl curl_easy_setopt CURLOPT_CUSTOMREQUEST verb

      return exec_as_multi(ctxt)
    finally
      cleanup_context(ctxt)
    end
  else
    return remotecall(myid(), custom, url, verb, set_opt_blocking(options))
  end
end


##############################
# EXPORTED UTILS
##############################

function urlencode_query_params{T<:Tuple}(params::Vector{T})
  curl = curl_easy_init()
  if (curl == C_NULL) throw("curl_easy_init() failed") end

  querystr = urlencode_query_params(curl, params)

  curl_easy_cleanup(curl)

  return querystr
end
export urlencode_query_params

function urlencode_query_params{T<:Tuple}(curl, params::Vector{T})
  querystr = ""
  for x in params
    k,v = x
    if (v != "")
      ep = urlencode(curl, string(k)) * "=" * urlencode(curl, string(v))
    else
      ep = urlencode(curl, string(k))
    end

    if querystr == ""
      querystr = ep
    else
      querystr = querystr * "&" * ep
    end

  end
  return querystr
end


function urlencode(curl, s::String)
  b_arr = curl_easy_escape(curl, s, length(s))
  esc_s = bytestring(b_arr)
  curl_free(b_arr)
  return esc_s
end

function urlencode(s::String)
  curl = curl_easy_init()
  if (curl == C_NULL) throw("curl_easy_init() failed") end

  esc_s = urlencode(curl, s)
  curl_easy_cleanup(curl)
  return esc_s

end

urlencode(s::SubString) = urlencode(bytestring(s))

export urlencode

const DEFAULT_TIME_OUT = 600 # default timeout value at 10 minutes

function exec_as_multi(ctxt::ConnContext)
  curl = ctxt.curl
  curlm = curl_multi_init()

  if (curlm == C_NULL) error("Unable to initialize curl_multi_init()") end

  try
    if isa(ctxt.options.callback, Function) ctxt.options.callback(curl) end

    @ce_curlm curl_multi_add_handle curl

    n_active = Array(Cint,1)
    n_active[1] = 1

    request_timeout = 0.001 + (ctxt.options.request_timeout == 0.0 ? DEFAULT_TIME_OUT : ctxt.options.request_timeout)

    started_at = time()
    time_left = request_timeout

    # START curl_multi_perform  mode

    cmc = curl_multi_perform(curlm, n_active);
    while (n_active[1] > 0) &&  (time_left > 0)
      nb1 = ctxt.bytes_recd
      cmc = curl_multi_perform(curlm, n_active);
      if(cmc != CURLM_OK) error ("curl_multi_perform() failed: " * bytestring(curl_multi_strerror(cmc))) end

      nb2 = ctxt.bytes_recd

      nb2 > nb1 ? yield() : sleep(0.005)

      time_left = request_timeout - (time() - started_at)
    end

    # END OF curl_multi_perform

    if (n_active[1] == 0)
      msgs_in_queue = Array(Cint,1)
      p_msg::Ptr{CURLMsg2} = curl_multi_info_read(curlm, msgs_in_queue)

      while (p_msg != C_NULL)
        #                println("Messages left in Q : " * string(msgs_in_queue[1]))
        msg = unsafe_load(p_msg)

        if (msg.msg == CURLMSG_DONE)
          ec = convert(Int, msg.data)
          if (ec != CURLE_OK)
            println("Result of transfer: " * string(msg.data))
            throw("Error executing request : " * bytestring(curl_easy_strerror(ec)))
          else
            process_response(ctxt)
          end
        end

        p_msg = curl_multi_info_read(curlm, msgs_in_queue)
      end
    else
      error ("request timed out")
    end

  finally
    curl_multi_remove_handle(curlm, curl)
    curl_multi_cleanup(curlm)
  end

  ctxt.resp
end

function exec_as_read(ctxt::ConnContext)
  curl  = ctxt.curl
  curlm = ctxt.curlm

  if isa(ctxt.options.callback, Function) ctxt.options.callback(curl) end

  ctxt.resp = Response()
  ctxt.resp.body = IOBuffer()

  # if there are bytes in the buffer, just return that
  data = ctxt.stream.buff.data
  n = length(data)
  if (n > 0)
    write(ctxt.resp.body, data)
    ctxt.stream.bytesRead += n
    ctxt.stream.buff = IOBuffer() # read everything so reset
    return ctxt.resp
  end

  # otherwise, read from stream and return whatever is available
  n_active = Array(Cint,1)
  n_active[1] = 1

  request_timeout = 0.001 + (ctxt.options.request_timeout == 0.0 ? DEFAULT_TIME_OUT : ctxt.options.request_timeout)
  started_at = time()
  time_left = request_timeout

  nb1 = ctxt.bytes_recd
  cmc = curl_multi_perform(curlm, n_active);
  if(cmc != CURLM_OK) error ("curl_multi_perform() failed: " * bytestring(curl_multi_strerror(cmc))) end
  nb2 = ctxt.bytes_recd
  while (nb2 == nb1) &&  (time_left > 0) && (n_active[1] > 0)
    yield() # let other processes run
    nb1 = ctxt.bytes_recd
    cmc = curl_multi_perform(curlm, n_active);
    if(cmc != CURLM_OK) error ("curl_multi_perform() failed: " * bytestring(curl_multi_strerror(cmc))) end

    nb2 = ctxt.bytes_recd

    time_left = request_timeout - (time() - started_at)
  end

  if (n_active[1] < 1)
    msgs_in_queue = Array(Cint,1)
    p_msg::Ptr{CURLMsg2} = curl_multi_info_read(curlm, msgs_in_queue)

    while (p_msg != C_NULL)
      msg = unsafe_load(p_msg)
      if (msg.msg == CURLMSG_DONE)
        ec = convert(Int, msg.data)
        if (ec != CURLE_OK)
          throw("Error executing request : " * bytestring(curl_easy_strerror(ec)))
        else
          ctxt.stream.state = :DONE
        end
      end
      p_msg = curl_multi_info_read(curlm, msgs_in_queue)
    end
  elseif (time_left <= 0)
    throw("darn it we timed out")
  end


  data = ctxt.stream.buff.data
  n = length(data)
  write(ctxt.resp.body, data)
  ctxt.stream.buff = IOBuffer() # read everything so reset
  ctxt.stream.bytesRead += n
  process_response(ctxt)
  return ctxt.resp
end

# disconnect the curl / curlm, create new ones, try again!
# use bytes read to figure out the range we need
# TODO: this doesn't work with S3 right now since we also need to redo all the authentication
# header stuff when we reset...
function resetStream(ctxt::ConnContext)
  url = ctxt.url
  disconnect(ctxt)

  ctxt2 = connect(url)
  curl = ctxt2.curl
  # make another conenction and set the current context's curls to
  # the new connection
  ctxt.curl = curl
  ctxt.curlm = ctxt2.curlm

  # change the range since some bytes have already been read
  @ce_curl curl_easy_setopt CURLOPT_RANGE "$(ctxt.stream.bytesRead)-"

  ctxt.stream.state = :CONNECTED
end

# TODO: timeout implementation, error recovery
function exec_as_stream(ctxt::ConnContext, numBytes::Int64)
  curl  = ctxt.curl
  curlm = ctxt.curlm

  if isa(ctxt.options.callback, Function) ctxt.options.callback(curl) end

  # array of bytes to return
  bytes = Uint8[]

  # read bytes from buffer until buffer is empty
  bytesLeft = numBytes
  data = ctxt.stream.buff.data
  last = (bytesLeft < length(data)) ? bytesLeft : length(data) # min of numBytes and end of the buffer
  if (last > 0) # there's data in the buffer for us to read
    bytes = data[1:last]
    ctxt.stream.buff.data = data[last+1:end] # remove the bytes we've read from the buffer
  end
  bytesLeft -= last

  # if our buffer ran out, we need to get more data from curl
  request_timeout = 0.001 + (ctxt.options.request_timeout == 0.0 ? DEFAULT_TIME_OUT : ctxt.options.request_timeout)
  timeLeft = request_timeout
  if (bytesLeft > 0)
    n_active = Array(Cint,1)
    n_active[1] = 1

    startTime = time()
    while (n_active[1] > 0) && (bytesLeft > 0)
      nb1 = ctxt.bytes_recd # bytes pre-curl
      cmc = curl_multi_perform(curlm, n_active);
      if(cmc != CURLM_OK) error ("curl_multi_perform() failed: " * bytestring(curl_multi_strerror(cmc))) end
      nb2 = ctxt.bytes_recd # bytes post-curl

      timeLeft = request_timeout - (time() - startTime)

      if (nb2 > nb1) # had stuff to read
        data = ctxt.stream.buff.data
        last = (bytesLeft < length(data)) ? bytesLeft : length(data)
        bytes = [bytes; data[1:last]] # concat
        ctxt.stream.buff.data = data[(last+1):end] # remove the bytes we've read from the buffer
        startTime = time() # reset our timer
        bytesLeft -= last  # bytes left to read
      else # failed to read stuff, just yield or timeout
        yield()
      end

    end # while

    # check curl_multi_perform's results (check if something went wrong or if the transfer is actually done)
    if (n_active[1] < 1)
      print("TF ")
      msgs_in_queue = Array(Cint,1)
      p_msg::Ptr{CURLMsg2} = curl_multi_info_read(curlm, msgs_in_queue)

      while (p_msg != C_NULL)
        msg = unsafe_load(p_msg)

        if (msg.msg == CURLMSG_DONE)
          ec = convert(Int, msg.data)
          if (ec != CURLE_OK)
            if (ec == 56) # recv error, need to reset connection
              println("recv error, trying again")
              ctxt.stream.bytesRead += length(bytes)
              ctxt.stream.errs += 1
              print("reset ")
              resetStream(ctxt)
              if (ctxt.stream.errs > ctxt.options.max_errs)
                throw("oh no too many errors occured ($(ctxt.stream.errs))")
              end
              return [bytes; exec_as_stream(ctxt, bytesLeft)]
            else
              println("Context:\n $(ctxt)")
              println("Bytes:\n $(bytestring(bytes))")
              flush(STDOUT)
              throw("Uknown error executing request : " * bytestring(curl_easy_strerror(ec)))
            end
          else
            ctxt.stream.state = :DONE_DOWNLOADING
          end
        end

        p_msg = curl_multi_info_read(curlm, msgs_in_queue)
      end

      # transfer stopped unsuccessfuly, need to restart
      if(ctxt.stream.state != :DONE_DOWNLOADING)
        ctxt.stream.bytesRead += length(bytes)
        ctxt.stream.errs += 1
        if (ctxt.stream.errs > ctxt.options.max_errs)
          throw("oh no too many errors occured ($(ctxt.stream.errs))")
        end
        println("uh oh, an error occured")
        return [bytes; exec_as_stream(ctxt, bytesLeft)]
      end
    elseif (timeLeft <= 0 && bytesLeft > 0) # timed out
      ctxt.stream.bytesRead += length(bytes)
      ctxt.stream.errs += 1
      print("reset ")
      resetStream(ctxt)
      if (ctxt.stream.errs > ctxt.options.max_errs)
        throw("oh no too many errors occured ($(ctxt.stream.errs))")
      end
      return [bytes; exec_as_stream(ctxt, bytesLeft)]
    end
  end # if (bytesLeft > 0)

  ctxt.stream.bytesRead += length(bytes)
  if (ctxt.stream.state == :DONE_DOWNLOADING) && (length(ctxt.stream.buff.data) == 0)
    ctxt.stream.state = :DONE
  end
  # process HTTP codes and time for the request
  process_response(ctxt)
  return bytes
end

end # module
