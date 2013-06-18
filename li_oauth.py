import oauth2 as oauth
import urlparse 
 
consumer_key           = "bf90vk5plazq"
consumer_secret        = "pfuKhimidCiHakxj"
consumer = oauth.Consumer(consumer_key, consumer_secret)
client = oauth.Client(consumer)

request_token_url      = 'https://api.linkedin.com/uas/oauth/requestToken'
resp, content = client.request(request_token_url, "POST")
if resp['status'] != '200':
    raise Exception("Invalid response %s." % resp['status'])

request_token = dict(urlparse.parse_qsl(content))


print "Request Token:"
print "    - oauth_token        = %s" % request_token['oauth_token']
print "    - oauth_token_secret = %s" % request_token['oauth_token_secret']
print 


authorize_url =      'https://api.linkedin.com/uas/oauth/authorize'
print "Go to the following link in your browser:"
print "%s?oauth_token=%s" % (authorize_url, request_token['oauth_token'])
print 


accepted = 'n'
while accepted.lower() == 'n':
    accepted = raw_input('Have you authorized me? (y/n) ')
oauth_verifier = raw_input('What is the PIN? ')


access_token_url = 'https://api.linkedin.com/uas/oauth/accessToken'
token = oauth.Token(request_token['oauth_token'], request_token['oauth_token_secret'])
token.set_verifier(oauth_verifier)
client = oauth.Client(consumer, token)
 
resp, content = client.request(access_token_url, "POST")
access_token = dict(urlparse.parse_qsl(content))
 
print "Access Token:"
print "    - oauth_token        = %s" % access_token['oauth_token']
print "    - oauth_token_secret = %s" % access_token['oauth_token_secret']
print
print "You may now access protected resources using the access tokens above."
print

# -----------------------------------------------------

url = "http://api.linkedin.com/v1/people/~"

consumer = oauth.Consumer(
     key="bf90vk5plazq",
     secret="pfuKhimidCiHakxj")
     
token = oauth.Token(
     key="ceae47ba-1830-4f9b-a132-a1a998fe230a", 
     secret="4aa8e08a-56d3-42a7-94d1-66801e7cba16")


client = oauth.Client(consumer, token)


print "\n********Get the connections********"
response = linkedin.make_request(client,"http://api.linkedin.com/v1/people/~/connections", {"x-li-format":'json'})
print response



# resp, content = client.request(url)
# print resp
# print content


# ---------------------------------------------------

import oauth2 as oauth
import time
import simplejson
 
url = "http://api.linkedin.com/v1/people/~/connections"
 
consumer = oauth.Consumer(
        key="bf90vk5plazq",
        secret="pfuKhimidCiHakxj")
        
token = oauth.Token(
        key="ceae47ba-1830-4f9b-a132-a1a998fe230a", 
        secret="4aa8e08a-56d3-42a7-94d1-66801e7cba16")
 
 
client = oauth.Client(consumer, token)
# body = {"comment":"Posting from the API using JSON",
#                 "content":{
#                         "submitted-url":"http://www.google.md/#q=Nicolas+Steno&ct=steno12-hp&oi=ddle&bav=on.2,or.r_gc.r_pw.,cf.osb&fp=8c5a975d815425a&biw=1920&bih=881"
#                 },
#                 "visibility":{"code":"anyone"}
#         }
           
 
resp, content = client.request(url, {"x-li-format":'json'})
print resp
print content


