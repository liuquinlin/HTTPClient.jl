using HTTPClient.HTTPC

println("Testing...")
urls = ASCIIString[]
numFiles = 5
for i=1:numFiles
    push!(urls, "davis-test.s3.amazonaws.com")
end

s = HTTPC.connect(urls)
#while !HTTPC.isDone(s)
try
    r = HTTPC.getbytes(s, 1000)
    display(r)
finally
    #end
    HTTPC.disconnect(s)
end