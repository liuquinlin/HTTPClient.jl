module HTTPC

using Compat
using LibCURL
using LibCURL.Mime_ext

import Base.convert, Base.show, Base.get, Base.trace

export init, cleanup, get, put, post, trace, delete, head, options
export connect, disconnect, getbytes, isDone
export RequestOptions, Response, ConnContext, StreamData, StreamGroup

def_rto = 0.0

##############################
# Struct definitions
##############################

type RequestOptions
    blocking::Bool
    query_params::Vector{Tuple}
    request_timeout::Float64
    callback::Union(Function,Bool)
    content_type::String
    headers::Vector{Tuple}
    ostream::Union(IO, String, Nothing)
    auto_content_type::Bool
    max_errs::Int64
    timeout::Float64
    ctimeout::Float64

    const def_max_errs = 10
    const def_timeout  = 10
    const def_ctimeout = 60
    RequestOptions(; blocking=true, query_params=Array(Tuple,0), request_timeout=def_rto, callback=null_cb, content_type="", headers=Array(Tuple,0), ostream=nothing, auto_content_type=true, max_errs=def_max_errs, timeout=def_timeout, ctimeout=def_ctimeout) =
        new(blocking, query_params, request_timeout, callback, content_type, headers, ostream, auto_content_type, max_errs, timeout, ctimeout)
end

type Response
    body
    headers::Dict{String, Vector{String}}
    http_code
    total_time
    bytes_recd::Integer

    Response() = new(nothing, Dict{String, Vector{String}}(), 0, 0.0, 0)
end
function show(io::IO, o::Response)
    println(io, "HTTP Code   :", o.http_code)
    println(io, "RequestTime :", o.total_time)
    println(io, "Headers     :")
    for (k,vs) in o.headers
        for v in vs
            println(io, "    $k : $v")
        end
    end
    if isa(o.body, Vector{Uint8})
        println(io, "Length of body : ", length(o.body))
    else
        println(io, "Length of body : ", o.bytes_recd)
    end
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
#    bytes_streamed::Int64
    bytes_read::Int64
    bytes_wanted::Int64
    buff::IOBuffer
    state::Symbol
    numErrs::Int64
    lastTime::Float64
 
    const MAX_BUFF_SIZE = 16*1024 # 16KiB
    StreamData() = new(0, 0, IOBuffer(), :NONE, 0, 0)
end
function show(io::IO, o::StreamData)
#    print(io, "streamed: ", o.bytes_streamed)
    print(io, "read: ", o.bytes_read)
    print(io, ", wanted: ", o.bytes_wanted)
    print(io, ", numErrs: ", o.numErrs)
    print(io, ", lastTime: ", o.lastTime)
    println(io, ", state: ", o.state)
    print(io, o.buff)
end

type ConnContext
    curl::Ptr{CURL}
    url::String
    slist::Ptr{Void}
    rd::ReadData
    resp::Response
    options::RequestOptions
    close_ostream::Bool
    stream::StreamData

    ConnContext(options::RequestOptions) = new(C_NULL, "", C_NULL, ReadData(), Response(), options, false, StreamData())
end
function show(io::IO, o::ConnContext)
    print(io, "URL : ", o.url)
    print(io, ", CURL : ", o.curl)
    println(io, ", slist : ", o.slist)
    println(io, "ReadData : ", o.rd)
    println(io, "OStream  : ", o.close_ostream)
    println("***   Response  ***")
    print(io, o.resp)
    println("***   Options   ***")
    println(io, o.options)
    println("*** Stream Data ***")
    println(io, o.stream)
end

#= type GroupOpts
    max_errs::Int64
    timeout::Float64
    ctimeout::Float64

    GroupOpts(max_errs, timeout, ctimeout) = new(max_errs, timeout, ctimeout)
end
function show(io::IO, o::GroupOpts)
    print(io, "max errs: ", o.max_errs)
    print(io, ", timeout: ", o.timeout)
    println(io, ", connect timeout: ", o.ctimeout)
end =#

type StreamGroup
    ctxts::Vector{ConnContext}
    curlm::Ptr{CURL}
    share::Ptr{CURL}
    running::Vector{Cint}
    curlToCtxt::Dict{Ptr{CURL}, ConnContext}

    StreamGroup(curlm, share) = new(ConnContext[], curlm, share, Cint[], Dict{Ptr{CURL}, ConnContext}())
end
function show(io::IO, o::StreamGroup)
    println("#===============================#")
    println("#          Stream Group         #")
    println("#===============================#")
    println(io, "multi handle : ", o.curlm)
    println(io, "share handle : ", o.share)
#    println(io, "curlToCtxt   : ", o.curlToCtxt)
    i = 0
    for ctxt in o.ctxts
        i += 1
        println("---------------------")
        println(io, "|     Context $(i):    |")
        println("---------------------")
        print(io, ctxt)
    end
end

immutable CURLMsgResult
  msg::CURLMSG
  easy_handle::Ptr{CURL}
  result::CURLcode
end

##############################
# Callbacks
##############################

function write_cb(buff::Ptr{Uint8}, sz::Csize_t, n::Csize_t, p_ctxt::Ptr{Void})
#    println("@write_cb")
    ctxt = unsafe_pointer_to_objref(p_ctxt)
    nbytes = sz * n
    if (ctxt.stream.state == :NONE)
        write(ctxt.resp.body, buff, nbytes)
    else
        ctxt.stream.buff = IOBuffer()
#        ctxt.stream.bytes_streamed += nbytes
        write(ctxt.stream.buff, buff, nbytes)
    end
    ctxt.resp.bytes_recd += nbytes
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
            k = strip(m.captures[1])
            v = strip(m.captures[2])
            if haskey(ctxt.resp.headers, k)
                push!(ctxt.resp.headers[k], v)
            else
                ctxt.resp.headers[k] = (String)[v]
            end
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
        o2 = RequestOptions()
        for n in filter(x -> !(x in [:ostream, :blocking]),fieldnames(o2))
            setfield!(o2, n, deepcopy(getfield(options, n)))
        end
        o2.blocking = true
        o2.ostream = options.ostream
        return o2
end

function get_ct_from_ext(filename)
    fparts = split(basename(filename), ".")
    if (length(fparts) > 1)
        if haskey(MimeExt, fparts[end]) return MimeExt[fparts[end]] end
    end
    return false
end

function setup_curl(ctxt::ConnContext)
    ctxt.curl = curl_easy_init()
    if (ctxt.curl == C_NULL) throw("curl_easy_init() failed") end

    if length(ctxt.options.query_params) > 0
        qp = urlencode_query_params(ctxt.curl, ctxt.options.query_params)
        ctxt.url = ctxt.url * "?" * qp
    end

    @ce_curl curl_easy_setopt CURLOPT_FOLLOWLOCATION 1

    @ce_curl curl_easy_setopt CURLOPT_MAXREDIRS 5

    @ce_curl curl_easy_setopt CURLOPT_URL ctxt.url
    @ce_curl curl_easy_setopt CURLOPT_WRITEFUNCTION c_write_cb

    p_ctxt = pointer_from_objref(ctxt)

    @ce_curl curl_easy_setopt CURLOPT_WRITEDATA p_ctxt

    @ce_curl curl_easy_setopt CURLOPT_HEADERFUNCTION c_header_cb
    @ce_curl curl_easy_setopt CURLOPT_HEADERDATA p_ctxt

    @ce_curl curl_easy_setopt CURLOPT_HTTPHEADER ctxt.slist
end

function setup_easy_handle(url, options::RequestOptions)
    ctxt = ConnContext(options)

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

    ctxt.url = url
    setup_curl(ctxt)

    if isa(options.ostream, String)
        ctxt.resp.body = open(options.ostream, "w+")
        ctxt.close_ostream = true
    elseif isa(options.ostream, IO)
        ctxt.resp.body = options.ostream
    else
        ctxt.resp.body = IOBuffer()
    end

    return ctxt
end

function cleanup_easy_context(ctxt::Union(ConnContext,Bool))
    if isa(ctxt, ConnContext)
        if (ctxt.slist != C_NULL)
            curl_slist_free_all(ctxt.slist)
            ctxt.slist = C_NULL
        end

        if (ctxt.curl != C_NULL)
            curl_easy_cleanup(ctxt.curl)
            ctxt.curl = C_NULL
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
            cleanup_easy_context(ctxt)
        end
    else
        return remotecall(myid(), get, url, set_opt_blocking(options))
    end
end



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
        cleanup_easy_context(ctxt)
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
            cleanup_easy_context(ctxt)
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
            cleanup_easy_context(ctxt)
        end
    else
        return remotecall(myid(), custom, url, verb, set_opt_blocking(options))
    end
end

##############################
# STREAMING FUNCTIONS
##############################

function connect(url::String, options::RequestOptions=RequestOptions())
    return connect([url], options)
end

function connect{T<:String}(urls::Vector{T}, options::RequestOptions=RequestOptions())
    curlm = curl_multi_init()
    if (curlm == C_NULL) error("Unable to initialize curl_multi_init()") end

    share = curl_share_init()
    if (share == C_NULL) error("Unable to initialize curl_share_init()") end

    group = StreamGroup(curlm, share)
    group.running = Cint[length(urls)]

    ctxts = ConnContext[]
    for url in urls
        ctxt = setup_easy_handle(url, options)
        ctxt.stream.state = :CONNECTED
        @ce_curl  curl_easy_setopt CURLOPT_HTTPGET 1
        @ce_curl  curl_easy_setopt CURLOPT_SHARE share
        @ce_curlm curl_multi_add_handle ctxt.curl
        push!(group.ctxts, ctxt)
        group.curlToCtxt[ctxt.curl] = ctxt
    end


    return group
end

function disconnect(group::StreamGroup)
    for ctxt in group.ctxts
        curl_multi_remove_handle(group.curlm, ctxt.curl)
        cleanup_easy_context(ctxt)
        ctxt.stream.state = :NONE
    end
    curl_multi_cleanup(group.curlm)
    curl_share_cleanup(group.share)
end

function get(group::StreamGroup)
    error("this method is currently unsupported")
end

function getbytes(group::StreamGroup, numBytes::Int64)
    numCtxts = length(group.ctxts)
    return getbytes(group, [numBytes for _=1:numCtxts])
end

function resetContext(group::StreamGroup, ctxt::ConnContext)
    delete!(group.curlToCtxt, ctxt.curl)

    curlm = group.curlm
    curl_multi_remove_handle(curlm, ctxt.curl)
    curl_easy_cleanup(ctxt.curl)

    setup_curl(ctxt)
    @ce_curl curl_easy_setopt CURLOPT_HTTPGET 1
    @ce_curl curl_easy_setopt CURLOPT_RANGE "$(ctxt.resp.bytes_recd)-"
    @ce_curl curl_easy_setopt CURLOPT_SHARE group.share
    group.curlToCtxt[ctxt.curl] = ctxt
    @ce_curlm curl_multi_add_handle ctxt.curl
    ctxt.stream.lastTime = time()
    ctxt.stream.state    = :CONNECTED
end

function getbytes(group::StreamGroup, numBytes::Vector{Int64})
    ctxts = group.ctxts
    numStreams = length(ctxts)
    @assert numStreams == length(numBytes)
    # each ctxt will return an array of bytes in its Response
    for ctxt in ctxts 
        ctxt.resp.body = Uint8[] 
    end
    numDone = 0
    # read from each stream's local buffer
    for i=1:numStreams
        s = ctxts[i].stream
        r = ctxts[i].resp
        s.bytes_wanted = numBytes[i]
        data = s.buff.data
        last = min(s.bytes_wanted, length(data))
        if last > 0
            r.body  = data[1:last]
            s.buff.data = data[last+1:end]
            s.bytes_wanted -= last
            s.bytes_read   += last
        end

        # check for streams that are completely finished (empty)
        if s.state == :DONE_DOWNLOADING && s.bytes_read == r.bytes_recd
            s.state = :DONE
        end

        # unpause connections that still need bytes and start timer
        if s.bytes_wanted > 0 && s.state != :DONE
            curl_easy_pause(ctxts[i].curl, CURLPAUSE_CONT)
            s.lastTime = time()
        # count number of connections that don't need more bytes
        else
            numDone += 1
        end
    end

    # get new data from the connections
    const MAX_TIMEOUT = 30 * 24 * 3600.0 # one month
    timeout  = ctxts[1].options.timeout
    timeout  = ( timeout == 0 ? MAX_TIMEOUT : timeout )
    ctimeout = ctxts[1].options.ctimeout
    ctimeout = ( ctimeout == 0 ? MAX_TIMEOUT : ctimeout )
    rtimeout = ctxts[1].options.request_timeout
    rtimeout = ( rtimeout == 0 ? MAX_TIMEOUT : rtimeout )
    
    max_errs = ctxts[1].options.max_errs
    while numDone < numStreams
        oldRunning = group.running[1]
        curlmcode = curl_multi_perform(group.curlm, group.running)
        if (curlmcode != CURLM_OK)
            error("curl_multi_perform failed " * bytestring(curl_multi_strerror(curlmcode))) 
        end

        # check for finished transfers / handle errors
        if (oldRunning > group.running[1])
            while (p_msg::Ptr{CURLMsgResult} = curl_multi_info_read(group.curlm, Cint[0])) != C_NULL
                msg = unsafe_load(p_msg)
                curl = msg.easy_handle
                if msg.msg == CURLMSG_DONE
                    curlcode = msg.result
                    ctxt = group.curlToCtxt[curl]
                    s = ctxt.stream
                    if (curlcode == CURLE_RECV_ERROR)
                        s.numErrs += 1
                        if (s.numErrs > max_errs)
                            error("too many errors, aborting")
                        end
                        println("recv error, retrying")
                        resetContext(group, ctxts[i])
                    elseif (curlcode != CURLE_OK)
                        error("CURLMsg error: " * bytestring(curl_easy_strerror(curlcode)))
                    end
                    s.state = :DONE_DOWNLOADING
                end
            end
        end

        # read any new information from the local buffer
        numDone = 0
        for i=1:numStreams
            s = ctxts[i].stream
            r = ctxts[i].resp
            if s.state == :DONE # don't bother with finished ones
                numDone += 1
                continue
            end
            data = s.buff.data
            last = min(s.bytes_wanted, length(data))
            if last > 0
                if s.state == :CONNECTED
                    s.state = :DOWNLOADING
                end
                r.body = [ r.body ; data[1:last] ]
                s.buff.data = data[last+1:end]
                s.bytes_wanted -= last
                s.bytes_read   += last
                s.lastTime = time()
            elseif s.bytes_wanted > 0
                # check for timeouts
                timeElap = time() - s.lastTime
                if (timeElap > rtimeout)
                    error("request timed out")
                end
                if (s.state == :DOWNLOADING && timeElap > timeout) || (s.state == :CONNECTED && timeElap > ctimeout)
                    s.numErrs += 1
                    if (s.numErrs > max_errs)
                        error("too many errors, aborting")
                    end
                    if s.state == :DOWNLOADING
                        println("timed out while streaming: $(timeElap)")
                    elseif s.state == :CONNECTED
                        println("timed out while connecting: $(timeElap)")
                    end
                    resetContext(group, ctxts[i])
                end
            end

            # pause transfers if we don't need more bytes right now
            if s.bytes_wanted == 0
                curl_easy_pause(ctxts[i].curl, CURLPAUSE_ALL)
                numDone += 1
            end

            # check for streams that are completely finished (empty)
            if s.state == :DONE_DOWNLOADING && s.bytes_read == r.bytes_recd
                s.state = :DONE
            end
        end # for
        sleep(.005)
    end # while

    # return the array of response objects
    for i=1:numStreams
        process_response(ctxts[i])
    end
    return [ ctxts[i].resp for i=1:numStreams ]
end

function isDone(group::StreamGroup)
    for ctxt in group.ctxts
        if (ctxt.stream.state != :DONE)
            return false
        end
    end
    return true
    #= alternatively:
    return (group.running[1] == 0)
    =#
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
    b_arr = curl_easy_escape(curl, s, sizeof(s))
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


function exec_as_multi(ctxt)
    curl = ctxt.curl
    curlm = curl_multi_init()

    if (curlm == C_NULL) error("Unable to initialize curl_multi_init()") end

    try
        if isa(ctxt.options.callback, Function) ctxt.options.callback(curl) end

        @ce_curlm curl_multi_add_handle curl

        n_active = Array(Cint,1)
        n_active[1] = 1

        no_to = 30 * 24 * 3600.0
        request_timeout = 0.001 + (ctxt.options.request_timeout == 0.0 ? no_to : ctxt.options.request_timeout)

        started_at = time()
        time_left = request_timeout

        cmc = curl_multi_perform(curlm, n_active);
        while (n_active[1] > 0) &&  (time_left > 0)
            nb1 = ctxt.resp.bytes_recd
            cmc = curl_multi_perform(curlm, n_active);
            if(cmc != CURLM_OK) error ("curl_multi_perform() failed: " * bytestring(curl_multi_strerror(cmc))) end

            nb2 = ctxt.resp.bytes_recd

            if (nb2 > nb1)
                yield() # Just yield to other tasks
            else
                sleep(0.005) # Just to prevent unnecessary CPU spinning
            end

            time_left = request_timeout - (time() - started_at)
        end

        if (n_active[1] == 0)
            msgs_in_queue = Array(Cint,1)
            p_msg::Ptr{CURLMsgResult} = curl_multi_info_read(curlm, msgs_in_queue)

            while (p_msg != C_NULL)
                msg = unsafe_load(p_msg)

                if (msg.msg == CURLMSG_DONE)
                    ec = msg.result
                    if (ec != CURLE_OK)
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

println("If this prints, you're using the right version of HTTPClient.jl")

end
