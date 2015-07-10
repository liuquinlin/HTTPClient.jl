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
        last = min(start+chunkSize-1, length(correct))
        @test r.body == correct[start:last]
        streamed = [ streamed ; r.body ]
        i += 1
    end
    @test streamed == correct
    HTTPC.disconnect(s)
end

function test_stream_many_files(urls::Vector{ASCIIString}, chunkSize::Vector{Int64}; sameFile=false)
    options = RequestOptions(timeout=3, ctimeout=30)
    correct = HTTPC.get(urls[1]).body.data
    s = HTTPC.connect(urls, options)
    j = 0
    startTime = time()
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

        if (sameFile)
            returnContentsMatch = true
            for i=2:length(resps)
                if !(resps[i-1].body == resps[i].body)
                    returnContesntsMatch = false
                    break
                end
            end
            @test returnContentsMatch
            
            returnContentsCorrect = true
            start = j*chunkSize[1]+1
            last = min(start+chunkSize[1]-1, length(correct))
            for i=1:length(resps)
                if (resps[i].body != correct[start:last])
                    returnContentsCorrect = false
                    break
                end
            end
            @test returnContentsCorrect
        end
        j += 1
    end
    finishTime = time()

    HTTPC.disconnect(s)
    println("time elapsed: $(finishTime - startTime)")
end

function test_join(urls::Vector{ASCIIString}, chunkSize::Vector{Int64})
    options = RequestOptions(timeout=3, ctimeout=30)
    conns = StreamGroup[]
    for i=1:length(urls)
        push!(conns, HTTPC.connect(urls[i], options))
    end
    conns = nothing

    startTime = time()
    s = HTTPC.join(conns)
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
    finishTime = time()

    HTTPC.disconnect(s)
    println("time elapsed: $(finishTime - startTime)")
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
    test_stream_many_files(urls, chunkSize, sameFile=true)

    println("--- STREAM 2048 SMALL FILES ---")
    urls = [ "davis-test.s3.amazonaws.com/testing.txt" for _=1:2048 ]
    chunkSize = [ 16 for _=1:2048 ]
    test_stream_many_files(urls, chunkSize, sameFile=true)

    println("--- STREAM TWO DIFFERENT FILES ---")
    urls = [ "davis-test.s3.amazonaws.com/testing.txt", "davis-test.s3.amazonaws.com/bigtest.txt" ]
    chunkSize = [ 16 , 8*1024 ]
    test_stream_many_files(urls, chunkSize)

    println("--- STREAM 512 BIG FILES ---")
    urls = [ "davis-test.s3.amazonaws.com/bigtest.txt" for _=1:512 ]
    chunkSize = [ 8*1024 for _=1:512 ]
    test_stream_many_files(urls, chunkSize, sameFile=true)

    println("--- STREAM 2048 BIG FILES ---")
    urls = [ "davis-test.s3.amazonaws.com/bigtest.txt" for _=1:2048 ]
    chunkSize = [ 8*1024 for _=1:2048 ]
    test_stream_many_files(urls, chunkSize, sameFile=true)

    println("--- STREAM 2048 BIG FILES WITH JOIN ---")
    test_join(urls, chunkSize)

    println("--- TESTS DONE ---")
end

HelperTest.run_test(run_tests)