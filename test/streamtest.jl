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
end

function run_tests()
    println("--- CONNECTION TESTS ---")
    test_connect()
    println("--- STREAM ONE SMALL FILE ---")
    test_stream_one_file("davis-test.s3.amazonaws.com/testing.txt", 16)
    println("--- STREAM ONE LARGE FILE ---")
    test_stream_one_file("davis-test.s3.amazonaws.com/bigtest.txt", 1024*8)
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