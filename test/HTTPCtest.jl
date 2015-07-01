using HTTPClient.HTTPC

println("Testing...")
s = HTTPC.connect("www.wikipedia.com")
display(s)
HTTPC.disconnect(s)
s = HTTPC.connect(["www.google.com", "www.yahoo.com"])
display(s)
HTTPC.disconnect(s)