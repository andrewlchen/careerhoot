# Create your views here.

# Python
import oauth2 as oauth
import cgi
import simplejson as json
import datetime
import re
import urlparse 
import pprint

# Django
from django.shortcuts import render_to_response, get_object_or_404
from django.http import HttpResponseRedirect, HttpResponse
from django.conf import settings
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from django.template import RequestContext
from django.core.urlresolvers import reverse

# Custom
import linkedin_core
from introkick.models import *

consumer = oauth.Consumer(settings.LINKEDIN_TOKEN, settings.LINKEDIN_SECRET)
client = oauth.Client(consumer)

request_token_url = 'https://api.linkedin.com/uas/oauth/requestToken?scope=r_network+r_emailaddress'
access_token_url = 'https://api.linkedin.com/uas/oauth/accessToken'
authenticate_url = 'https://www.linkedin.com/uas/oauth/authenticate'

def index(request):
    return render_to_response('introkick/index.html', {'dummy_index' : "Login page placeholder."})

# /oauth_login
def oauth_login(request):
	# Step 1. Get the current hostname and port for the callback
	if request.META['SERVER_PORT'] == 443:
		current_server = "https://" + request.META['HTTP_HOST']
	else: 
		current_server = "http://" + request.META['HTTP_HOST']
		oauth_callback = current_server + "/introkick/oauth_login/oauth_authenticated"

	# Step 2. Get a request token from LinkedIn.
	resp, content = client.request("%s&oauth_callback=%s" % (request_token_url, oauth_callback), "GET")
	
	if resp['status'] != '200':
		raise Exception("Invalid response from LinkedIn.")

	# Step 3. Store the request token in a session for later use.
	request.session['request_token'] = dict(cgi.parse_qsl(content))

	# Step 4. Redirect the user to the authentication URL.
	url = "%s?oauth_token=%s" % (authenticate_url, 
    	request.session['request_token']['oauth_token'])

	return HttpResponseRedirect(url)

# /
@login_required
def home(request):
	html = '<html><body>'
	token = oauth.Token(request.user.get_profile().oauth_token, 
		request.user.get_profile().oauth_secret)
	client = oauth.Client(consumer, token)
	headers = {'x-li-format': 'json'}
	url  = "http://api.linkedin.com/v1/people/~:(id,first-name,last-name,email-address)"
	resp, content = client.request(url, "GET", headers=headers)
	profile = json.loads(content)
	html += profile['firstName'] + " " + profile['lastName'] + "<br/>" + profile['emailAddress'] + "<br/>" + profile['id']
	return HttpResponse(html)

# /oauth_logout
@login_required
def oauth_logout(request):
	# Log a user out using Django's logout function and redirect them back to the homepage.
    logout(request)
    return HttpResponseRedirect('/')


# /oauth_login/oauth_authenticate
def oauth_authenticated(request):

	# Step 1. Use the request token in the session to build a new client.
	token = oauth.Token(request.session['request_token']['oauth_token'],
		request.session['request_token']['oauth_token_secret'])

	if 'oauth_verifier' in request.GET:
		token.set_verifier(request.GET['oauth_verifier'])
	
	client = oauth.Client(consumer, token)

	# Step 2. Request the authorized access token from LinkedIn.
	resp, content = client.request(access_token_url, "GET")
	
	if resp['status'] != '200':
		print content
		raise Exception("Invalid response from LinkedIn.")

	access_token = dict(cgi.parse_qsl(content))
	# access_token = dict(urlparse.parse_qsl(content))

	headers = {'x-li-format': 'json'}
	token = oauth.Token(access_token['oauth_token'], 
		access_token['oauth_token_secret'])
	client = oauth.Client(consumer, token)
	resp, connections_temp = client.request("http://api.linkedin.com/v1/people/~/connections:(id,picture-url,first-name,last-name,location:(name),industry,positions:(title,company:(name)))", 
		"GET", headers=headers)

	resp, user_temp = client.request("http://api.linkedin.com/v1/people/~:(id,first-name,last-name,email-address)", 
		"GET", headers=headers)

	connections_dict_temp = json.loads(connections_temp)
	user_dict_temp = json.loads(user_temp)

	# Step 3. Lookup the user or create them if they don't exist.
	first_name = user_dict_temp["firstName"]
	last_name = user_dict_temp["lastName"]
	email = user_dict_temp["emailAddress"]
	user_id = user_dict_temp["id"]

	try:
		user = UserProfile.objects.get(user__username=user_id)
		user.login_count += 1
		user.save()
	except UserProfile.DoesNotExist:
		user = User.objects.create_user(
			username=user_id, 
			password=access_token['oauth_token_secret'])
		user.first_name=first_name
		user.last_name=last_name
		user.email=email
		userprofile = UserProfile()
		userprofile.user = user
		userprofile.oauth_token = access_token['oauth_token']
		userprofile.oauth_secret = access_token['oauth_token_secret']
		userprofile.login_count = 1
		userprofile.date_joined = timezone.now()
		# userprofile.user_mid = user_id
		# userprofile.email = email
		userprofile.save()

	# Now, authenticate the user and log them in using Django's 
	# pre-built functions for these things. 
	user = authenticate(username=user_id, 
		password=access_token['oauth_token_secret'])
	if user: 
		login(request, user)
		return HttpResponseRedirect('/introkick/home/')
		# return render_to_response('introkick/index.html', 
		# 	{
		# 	'first_name' : first_name, 
		# 	'last_name' : last_name,
		# 	'email' : email,
		# 	'user' : user.password
		# 	})
	else: 
		return render_to_response('introkick/index.html', 
			{
			'first_name' : first_name, 
			'last_name' : last_name,
			'email' : email,
			'login_fail' : "login failed."
			})

	# connections_list = connections_dict_temp['values']

	# temp_range_counter = []
	# j = 0

	# for i in range(len(connections_list)):
	# 	if ('private' == connections_list[i]['lastName']):
	# 		temp_range_counter.append(i)

	# for i in range(len(temp_range_counter)):
	# 	connections_list.pop(temp_range_counter[i]-j)
	# 	j += 1


	# connections_id = []
	# connections_firstName = []
	# connections_lastName = []
	# connections_location = []
	# connections_industry = []
	# connections_positions = []
	# connections_picture_url = []

	# for i in range(len(connections_list)):
	# 	try:
	# 		connections_id.append(connections_list[i]['id'])
	# 	except KeyError: 
	# 		connections_id.append('ID unspecified.')

	# 	try:
	# 		connections_firstName.append(connections_list[i]['firstName'])
	# 	except KeyError: 
	# 		connections_firstName.append('First name unspecified.')

	# 	try:
	# 		connections_lastName.append(connections_list[i]['lastName'])
	# 	except KeyError: 
	# 		connections_lastName.append('Last name unspecified.')

	# 	try:
	# 		connections_location.append(connections_list[i]['location']['name'])
	# 	except KeyError: 
	# 		connections_location.append('Location unspecified.')

	# 	try:
	# 		connections_industry.append(connections_list[i]['industry'])
	# 	except KeyError: 
	# 		connections_industry.append('Industry unspecified.')

	# 	try:
	# 		connections_positions.append([connections_list[i]['positions']['values'][0]['company']['name']])
	# 	except KeyError: 
	# 		connections_positions.append(['No company specified.'])

	# 	try:
	# 		connections_positions[i].append(connections_list[i]['positions']['values'][0]['title'])
	# 	except KeyError: 
	# 		connections_positions[i].append('No title specified.')

	# 	try:
	# 		connections_picture_url.append(connections_list[i]['pictureUrl'])
	# 	except KeyError: 
	# 		connections_picture_url.append('No picture given.')



	# connections_list_range = range(len(connections_list))

	# email = email(request)

	# return render_to_response('introkick/company.html', 
	# 	{'user' : "Introkick network for %s %s" % (first_name, last_name), 
	# 	'Email' : email,
	# 	'connections_list_range' : connections_list_range,
	# 	'connections_firstName' : connections_firstName,
	# 	'connections_lastName' : connections_lastName,
	# 	'connections_location' : connections_location,
	# 	'connections_industry' : connections_industry,
	# 	'connections_positions' : connections_positions,
	# 	'first_name' : first_name,
	# 	'last_name' : last_name
	# 	})





	# try:
	# 	u = UserProfile.objects.get(email=email)
	# except (KeyError, UserProfile.DoesNotExist):
		# Redisplay the login page.
	# 	return render_to_response('introkick/detail.html', {
	# 		'error_message': "You didn't enter a valid email address.",
	# 		}, context_instance=RequestContext(request))
	# else:
		# user.email = email_entered
		# user.save()
		# Always return an HttpResponseRedirect after successfully dealing
		# with POST data. This prevents data from being posted twice if a
		# user hits the Back button.
		# return HttpResponseRedirect(reverse('introkick.views.company'))

# first_name, last_name, email, connections_list_range, connections_firstName, connections_lastName, connections_location, connections_industry, connections_positions


def email(request):
	user = get_object_or_404(UserProfile, pk=user_id)
	try:
		user_email = user.email_set.get(pk=request.POST['email'])
	except(KeyError, Choice.DoesNotExist):
		return render_to_response('introkick/email.html', 
			{'error_message' : 'You didn\'t enter a valid email.', },
			context_instance=RequestContext(request))
	else:
		user.email = email
		user.save()
		return email

def company(request):
	return render_to_response('introkick/company.html', {'dummy_company' : "Company page placeholder"})
	# return login(request)
	# company_user = get_object_or_404(UserProfile, pk=user_id)

def industry(request, username):
	return HttpResponse("This is the post-login industry page.")

def detail(request, user_mid):
	mid = get_object_or_404(UserProfile, pk=user_mid)
	return render_to_response('introkick/detail.html', {'user_mid': mid},
		context_instance=RequestContext(request))
