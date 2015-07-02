using HTTPClient.HTTPC
using HelperTest
using Base.Test

function test_connect()
    urls = ["www.google.com", "www.yahoo.com", "www.bing.com"]
    s = HTTPC.connect(urls)
    @test length(s.ctxts) == length(urls)
    for i=1:length(urls)
        @test s.ctxts[i].url == urls[i]
        @test s.ctxts[i].stream.state == :CONNECTED
    end

    HTTPC.disconnect(s)
    for i=1:length(urls)
        @test s.ctxts[i].stream.state == :NONE
    end
end

function test_stream_one_file(url::ASCIIString, chunkSize::Int64)
    s = HTTPC.connect(url)
    correct = HTTPC.get(url).body.data
    streamed = []
    i = 0
    while !HTTPC.isDone(s)
        r = HTTPC.getbytes(s, chunkSize)[1]
        @test (r.http_code == 200 || r.http_code == 206)
        start = i*chunkSize+1
        last  = start+chunkSize-1 < length(correct) ? start+chunkSize-1 : length(correct)
        @test r.body == correct[start:last]
        streamed = [ streamed ; r.body ]
        i += 1
    end
    @test streamed == correct
    HTTPC.disconnect(s)
end

function test_stream_many_files(urls::Vector{ASCIIString}, chunkSize::Vector{Int64})
    s = HTTPC.connect(urls)
#=    correct = []
    for i=1:length(urls)
        push!(correct, HTTPC.get(urls[i]).body.data)
    end =#

    i = 0
    start = time()
    while !HTTPC.isDone(s)
        resps = HTTPC.getbytes(s, chunkSize)
        httpCodesAreOK = true
        for i=1:length(resps)
            if !(resps[i].http_code == 200 || resps[i].http_code == 206)
                httpCodesAreOK = false
                break
            end
        end
        @test httpCodesAreOK
    end
    println("time elapsed: $(time() - start)")
end

function run_tests()
    println("--- CONNECTION TESTS ---")
    test_connect()

    println("--- STREAM ONE SMALL FILE ---")
    test_stream_one_file("davis-test.s3.amazonaws.com/testing.txt", 16)

    println("--- STREAM ENTIRE FILE AT ONCE ---")
    test_stream_one_file("davis-test.s3.amazonaws.com/testing.txt", 1000)

    println("--- STREAM ONE LARGE FILE ---")
    test_stream_one_file("davis-test.s3.amazonaws.com/bigtest.txt", 1024*8)

    println("--- STREAM ONE LARGE FILE MANY BYTES AT A TIME ---")
    test_stream_one_file("davis-test.s3.amazonaws.com/bigtest.txt", 100000)

    println("--- STREAM 512 SMALL FILES ---")
    urls = [ "davis-test.s3.amazonaws.com/testing.txt" for _=1:512 ]
    chunkSize = [ 16 for _=1:512 ]
    test_stream_many_files(urls, chunkSize)

    println("--- STREAM 2048 SMALL FILES ---")
    urls = [ "davis-test.s3.amazonaws.com/testing.txt" for _=1:2048 ]
    chunkSize = [ 16 for _=1:2048 ]
    test_stream_many_files(urls, chunkSize)

    println("--- STREAM TWO DIFFERENT FILES ---")
    urls = [ "davis-test.s3.amazonaws.com/testing.txt", "davis-test.s3.amazonaws.com/bigtest.txt" ]
    chunkSize = [ 16 , 8*1024 ]
    test_stream_many_files(urls, chunkSize)

    println("--- TESTS DONE ---")
end

HelperTest.run_test(run_tests)

#=
println("Testing...")
urls = ASCIIString[]
const NUM_FILES  = 2048
const CHUNK_SIZE = 8*1024 # 8 KiB
const URL = "davis-test.s3.amazonaws.com/bigtest.txt"
for i=1:NUM_FILES
    push!(urls, URL)
end
ro = RequestOptions(timeout=3, ctimeout=30)
s = HTTPC.connect(urls, ro)
f = open("output.txt", "w")

tic()
try
    while !HTTPC.isDone(s)
        resp = HTTPC.getbytes(s, CHUNK_SIZE)
        for r in resp
            write(f, r.body)
        end
        println("read $(CHUNK_SIZE) bytes")
    end
finally
    HTTPC.disconnect(s)
    close(f)
end
toc()
=#