
'''

andrewlchen <--> Drew Chen <--> John Thirddegree
						\				|
						 \				|
						  <------> Jane Thirddegree
'''

# Import Python modules 
import oauth2 as oauth
import cgi
import simplejson as json
import datetime
from dateutil.relativedelta import relativedelta
import re
import urlparse 
# import pprint
# from MySQLdb import IntegrityError
from operator import itemgetter
import string
import random
import urllib
# import code

# Import Django modules 
from django.shortcuts import render_to_response, get_object_or_404
from django.http import HttpResponseRedirect, HttpResponse, Http404
from django.conf import settings
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User, Group, AnonymousUser
from django.contrib.auth.decorators import login_required
from django.template import RequestContext
from django.core.urlresolvers import reverse
from django.core.mail import send_mail, EmailMessage
from django.utils import timezone

# Import Custom modules - not needed any longer since oauth credential sit in settings 
# import linkedin_core

# Import models 
from introkick.models import *

# Import forms
from introkick.forms import *
from paypal.standard.forms import PayPalPaymentsForm
# from paypal.standard.ipn.signals import paypal_ipn_signal

'''
This pulls in my oauth token and secret, which was generated from the LinkedIn 
developer portal. It also sets the request token, access token, and authentication 
URLs
'''

consumer = oauth.Consumer(settings.LINKEDIN_TOKEN, settings.LINKEDIN_SECRET)
client = oauth.Client(consumer)

request_token_url = 'https://api.linkedin.com/uas/oauth/requestToken?scope=r_network+r_emailaddress+rw_nus'
access_token_url = 'https://api.linkedin.com/uas/oauth/accessToken'
authenticate_url = 'https://www.linkedin.com/uas/oauth/authenticate'


'''
This is the login page. It simply shows a "login with LinkedIn" button.
'''

def index(request):

	# grabs gid parameter from URL if it exists, and stores to session 
	request.session['gid'] = request.GET.get('gid', False)

	# captures URL and stores to session 
	share_url = 'http://' + request.get_host() + '/'
	request.session['share_url'] = share_url

	# renders login page 
	return render_to_response(
    	'introkick/index.html', {
    		'share_url' : share_url,
    	}, 
    	context_instance=RequestContext(request)
    )


# /oauth_login
def oauth_login(request):

	'''
	This processes the oauth-based login. It creates an oauth callback URL, then makes 
	the oauth call using that callback URL. It retrieves the oauth token. Then it 
	creates and directs to a URL consisting of the authentication URL with the oauth 
	token as a passed parameter. 
	'''

	# Step 1. Get current hostname and port for the callback

	if request.META['SERVER_PORT'] == 443:
		current_server = "https://" + request.META['HTTP_HOST']
	else: 
		current_server = "http://" + request.META['HTTP_HOST']
		oauth_callback = current_server + "/oauth_login/authenticate_user"

	# Step 2. Get a request token from LinkedIn.
	resp, content = client.request("%s&oauth_callback=%s" % (request_token_url, oauth_callback), "GET")
	
	if resp['status'] != '200':
		raise Exception("Invalid response from LinkedIn.")

	# Step 3. Store the request token in a session for later use.
	request.session['request_token'] = dict(cgi.parse_qsl(content))

	# Step 4. Redirect user to the authentication URL.
	url = "%s?oauth_token=%s" % (authenticate_url, 
    	request.session['request_token']['oauth_token'])

	return HttpResponseRedirect(url)


# /oauth_logout
@login_required
def oauth_logout(request):


	'''
	This logs the user out and invalidates the user's oauth token, so that they have to
	relogin by re-typing their credentials next time. 
	'''

	# Log a user out using Django's logout function and redirect them back to the homepage.

	token = oauth.Token(request.user.get_profile().oauth_token, 
		request.user.get_profile().oauth_secret)
	client = oauth.Client(consumer, token)

	logout(request)

	invalidate_token_url = 'https://api.linkedin.com/uas/oauth/invalidateToken?oauth_access_token=' + str(client)

	resp, content = client.request(invalidate_token_url, "GET")

	return HttpResponseRedirect('/')



'''
This completes oauth authentication by passing the oauth token and secret, along with
the oauth_verifier, back to LinkedIn, and LinkedIn send back the access_token. Using 
the access_token, we can then actually make API calls. 

Once authenticated, we call the basic profile service to figure out who the user is. 
We store the user's basic attributes, like first and last name, email, and mid. 
We also try to store the user's picture URL and public profile URL, if publicly exposed. 

Then, we try to retrieve that user from the DB. If the user is not found in the DB, we
create a new user with those credentials. 

If the user requested admission to a group via a URL GET request appending a group id, 
we process that request. 

If the user is a new user, we write to their NUS feed. 

Lastly, we authenticate and login the user into our IntroKick app, and redirect to 
/sync. 
'''

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

	# Step 3. Use that access token to build a new client, then return the client 

	token = oauth.Token(access_token['oauth_token'], 
		access_token['oauth_token_secret'])
	client = oauth.Client(consumer, token)

	return client, access_token


def pull_raw_user(request):

	'''
	Pulls raw, unprocessed user from LinkedIn API. 
	'''

	client, access_token = oauth_authenticated(request)

	headers = {'x-li-format': 'json'}

	resp, user_temp = client.request("http://api.linkedin.com/v1/people/~:(id,picture-url,public-profile-url,first-name,last-name,email-address,location:(name),industry,positions:(title,company:(name),is-current),site-standard-profile-request)", 
		"GET", headers=headers)

	user_dict_temp = json.loads(user_temp)

	return user_dict_temp, client, access_token



def create_attributes(request):

	'''
	Creates user attributes from raw, unprocessed user pulled from LinkedIn API.
	'''

	user_dict_temp, client, access_token = pull_raw_user(request)

	first_name = user_dict_temp["firstName"]
	last_name = user_dict_temp["lastName"]
	email = user_dict_temp["emailAddress"]
	user_id = user_dict_temp["id"]
	standard_profile_url = user_dict_temp['siteStandardProfileRequest']['url']
	user_picture_url = user_dict_temp.get('pictureUrl', 'No picture given')
	user_url = user_dict_temp.get('publicProfileUrl', '#')

	return {
		'first_name' : first_name, 
		'last_name' : last_name, 
		'email' : email, 
		'user_id' : user_id, 
		'standard_profile_url' : standard_profile_url, 
		'user_picture_url' : user_picture_url, 
		'user_url' : user_url, 
		'access_token' : access_token, 
		'client' : client,
	}


def get_gid(request):

	'''
	Returns the group id number if such number was appended to login URL in a GET request format. 
	'''

	return request.session.get('gid', False)


def login_get_user_gid_notification(request, user):

	'''
	Add or decline user's request to join a group iff user is a "returning" user, 
	i.e., she already exists in the DB. 
	'''

	# get or create mid to track invite count
	mid = get_or_create_mid(user.username)

	get_request = get_gid(request)

	if get_request:
		if mid.invite_count > 0:
			target_group = Group.objects.get(id=get_request)
			user.groups.add(target_group)
			mid.invite_count -= 1
			mid.save()
			request.session['user_notification'] = 'Congratulations on joining the group "%s"!' % target_group
		else: 
			request.session['user_notification'] = 'We\'re sorry, but %s %s was not invited to the group %s' % (user.first_name, user.last_name, Group.objects.get(id=get_request))
			del request.session['gid']


def login_create_user_gid_notification(request, user):

	'''
	Add or decline user's request to join a group iff user is a "new" user, 
	i.e., we must create this user in the DB. 
	'''

	# get or create mid to track invite count
	mid = get_or_create_mid(user.username)

	get_request = get_gid(request)

	if get_request: 
		mid.invite_count = 4
		mid.save()
		target_group = Group.objects.get(id=get_request)
		user.groups.add(target_group)
		request.session['user_notification'] = 'Congratulations on joining the group %s' % target_group


def write_to_NUS(request, attributes):

	'''
	Write to new user's NUS stream: "<John Doe> is now using <IntroKick> to get an edge on new opportunities through warm introductions."
	'''

	headers={'Content-Type' : 'application/xml'}

	standard_profile_url = attributes['standard_profile_url']

	client = attributes['client']

	NUS_update_string = "<a href=\"" + standard_profile_url + "\">" + attributes['first_name'] + " " + attributes['last_name'] + "</a> is now using <a href =\"" + request.session['share_url'] + "\">IntroKick</a> to get an edge on new opportunities through warm introductions."
	NUS_update_string_UTF8 = unicode(NUS_update_string, "utf-8")
	NUS_update_string_UTF8_escaped = cgi.escape(NUS_update_string_UTF8, quote=True)
	NUS_update_string_headers = "<activity locale=\"en_US\"><content-type>linkedin-html</content-type><body>" + NUS_update_string_UTF8_escaped + "</body></activity>"

	body = NUS_update_string_headers

	resp, user_temp = client.request("http://api.linkedin.com/v1/people/~/person-activities", 
	"POST", body=body, headers=headers)



def get_or_create_mid(mid_string):

	'''
	Get or create mid for purposes of managing viral invitations. 
	'''

	try: 
		mid = InviteMid.objects.get(mid=mid_string)
	except InviteMid.DoesNotExist:
		mid = InviteMid.objects.create(mid=mid_string)
		mid.invite_count = 0
		mid.save()

	return mid



# def set_expiry(request, userprofile):
# 	if userprofile.paid == True: 



def confirm_subscription(request, userprofile):

	if timezone.now() < userprofile.subs_expiry: 
		is_subscriber = True 
	else: 
		is_subscriber = False 

	return is_subscriber


# def reset_subs_expiry(request, userprofile):

# 	userprofile.subs_expiry: 

# 	current_user.subs_expiry = timezone.now() + relativedelta(months=1)
# 	current_user.save()

# 	request.session['onload_modal'] = 'paid'




def save_attributes(request, attributes):

	'''
	1. Fetch this user from DB, else if user doesn't exist then create this user in the DB. 

	2. Function call: If this user logged in with a "GET" request to join a group, process that request. 

	3. Function call: If it's a new user, write to that user's NUS stream. 
	'''

	try:
		# Fetch user's UserProfile
		userprofile = UserProfile.objects.get(user__username=attributes['user_id'])

		user = userprofile.user
		first_name = user.first_name
		# set_expiry(request, userprofile)
		is_subscriber = confirm_subscription(request, userprofile)

		if is_subscriber == True: 
			userprofile.login_count += 1
			userprofile.oauth_token = attributes['access_token']['oauth_token']
			userprofile.oauth_secret = attributes['access_token']['oauth_token_secret']
			userprofile.save()

			# Resave user's password because flushing oauth credentials on logout might have changed this on the next login. 
			user = userprofile.user # switch user variable from UserProfile to User to allow adding group after DB save
			user.set_password(attributes['access_token']['oauth_token_secret'])
			user.save()

	except UserProfile.DoesNotExist:
		# Create the user 
		user = User.objects.create_user(
			username=attributes['user_id'], 
			password=attributes['access_token']['oauth_token_secret'])
		user.first_name = attributes['first_name']
		user.last_name = attributes['last_name']
		user.email = attributes['email']
		user.date_joined = timezone.now()
		user.groups.create(name='%s %s\'s 1st degree connections' % (user.first_name, user.last_name))
		user.save()

		# Create the user's UserProfile object 
		userprofile = UserProfile()
		userprofile.user = user
		userprofile.oauth_token = attributes['access_token']['oauth_token']
		userprofile.oauth_secret = attributes['access_token']['oauth_token_secret']
		userprofile.subs_expiry = user.date_joined + relativedelta(days=14)
		userprofile.user_url = attributes['user_url']
		userprofile.user_picture_url = attributes['user_picture_url']
		userprofile.save()

		is_subscriber = True
		first_name = user.first_name

		# If user logged in with "GET" request to join a group, process that request. 
		login_create_user_gid_notification(request, user)

		# Write to user's NUS if it's a first-time user. 
		write_to_NUS(request, attributes) 

	if userprofile.paid == False: 
		# If user logged in with "GET" request to join a group, process that request. 
		login_get_user_gid_notification(request, user)
		request.session['onload_modal'] = 'free'
		request.session['show_popup'] = 'show'
		request.session['days_elapsed'] = 14 - (userprofile.subs_expiry - timezone.now()).days
		request.session['subs_expiry'] = userprofile.subs_expiry
	else: 
		# If user logged in with "GET" request to join a group, process that request. 
		# reset_subs_expiry(request, userprofile)
		login_get_user_gid_notification(request, user)

	request.session['first_name'] = first_name
	return is_subscriber



def upgrade(request, user_id): 

	first_name = request.session['first_name']
	checkout_form = subscribe_paypal(request, user_id)

	return render_to_response('introkick/upgrade.html', 
		{'first_name' : first_name,
		'checkout_form' : checkout_form.sandbox(),
		}, 
		context_instance=RequestContext(request))



def authenticate_user(request):

	'''
	1. Capture logged in user's attributes: 

	- first_name
	- last_name
	- email
	- user_id
	- user_picture_url
	- user_url
	- access_token

	2. Save attributes, process group admission requests, write to NUS

	3. If user is in free trial or is an active subscriber, then authenticate user 
	and log in using Django library. 

	4. Redirect to "sync" view
	'''

	attributes = create_attributes(request)
	is_subscriber = save_attributes(request, attributes)
	
	if not is_subscriber: 
		return HttpResponseRedirect(reverse('upgrade', 
			kwargs={'user_id' : attributes['user_id'], }
		))
	else: 

		user = authenticate(username=attributes['user_id'], 
			password=attributes['access_token']['oauth_token_secret'])
		if user: 
			login(request, user)
			return HttpResponseRedirect('/sync/')
		# else: 
		# 	return render_to_response('introkick/index.html', 
		# 		{
		# 		'first_name' : first_name, 
		# 		'last_name' : last_name,
		# 		'email' : email,
		# 		'error_message' : "Um, login failed."
		# 		})



'''
Here, we use our oauth token and secret to call the LinkedIn API. We pull all of the 
current user's connections. Then we process that list. 

First, we get rid of any connections that are not publicly exposed, where lastName is
private. Then we build lists to capture each data field: first name, last name, 
location, industry, companies, titles, picture URL, public profile URL. We iterate 
through the captured API call to build each individual list. For companies and 
titles, we do a sub-loop since a person can have more than one job / company at a time. 

Then we iterate through the current user's grid again and save the results to the DB. 
We run a sub-iteration within the larger grid iteration to save companies and titles
to the DB. 

With that done, we redirect to the main logged in homepage: /company. 
'''


def pull_user_grid(request):

	'''
	Pulls raw user grid and returns it as a list. 
	'''

	# Connect to LinkedIn API and pull signed in user's list of connections
	token = oauth.Token(request.user.get_profile().oauth_token, 
		request.user.get_profile().oauth_secret)
	client = oauth.Client(consumer, token)

	headers = {'x-li-format': 'json'}
	resp, grid_temp = client.request("http://api.linkedin.com/v1/people/~/connections:(id,picture-url,public-profile-url,first-name,last-name,location:(name),industry,positions:(title,company:(name),is-current))", 
		"GET", headers=headers)


	# Convert raw dictionary into a LIST OF DICTIONARIES, each dictionary is a connection. 
	grid_dict_temp = json.loads(grid_temp)
	grid_list_raw = grid_dict_temp['values']
	return grid_list_raw


def prune_user_grid(grid_list):

	'''
	From raw user grid, strip out any grid members who have shown last name as "private."
	'''

	# Prune list to eliminate empty profiles where connection has enabled privacy / invisibility 
	temp_range_counter = []
	j = 0
	grid_list_range = range(len(grid_list))

	for i in grid_list_range:
		if ('private' == grid_list[i]['lastName']):
			temp_range_counter.append(i)

	temp_range_counter_range = range(len(temp_range_counter))

	for i in temp_range_counter_range:
		grid_list.pop(temp_range_counter[i]-j)
		j += 1

	return grid_list


def id_generator(size=6, chars=string.ascii_uppercase + string.digits):

	''' 
	Generates a random 6 digit, uppercase string, used in function update_grid_to_DB(). 
	If a grid member's mid is obscured as private, then this will allow a unique 6 digit 
	string to be saved to the DB instead, preventing a situation of saving (and constantly
	overwriting) a DB entry labeled "User ID unspecified."
	'''
	return ''.join(random.choice(chars) for x in range(size))


def update_grid_to_DB(request):

	'''
	Takes pruned user grid and checks whether each grid member is already saved in 
	DB. If not, then save to DB. 

	If user is new and newly saved to DB, then get_or_create their company name and
	title in the Company model and add it to the user's company_set. 

	Finally, return the grid_list for further processing downstream. 
	'''

	current_user = request.user

	grid_list_raw = pull_user_grid(request)
	grid_list = prune_user_grid(grid_list_raw)
	grid_list_range = range(len(grid_list))

	for i in grid_list_range:
		try: 
			current_user_grid = Grid.objects.get(node_mid=grid_list[i].get('id'))
			if current_user not in current_user_grid.connectors.all():
				current_user_grid.connectors.add(current_user)
		except Grid.DoesNotExist: 
			current_user_grid = Grid.objects.create(node_mid=grid_list[i].get('id', id_generator()))
			current_user_grid.node_first_name = grid_list[i].get('firstName', 'First name unspecified')
			current_user_grid.node_last_name = grid_list[i].get('lastName', 'Last name unspecified')
			current_user_grid.node_location = grid_list[i]['location'].get('name', 'Location unspecified')
			current_user_grid.node_industry = grid_list[i].get('industry', 'Industry unspecified')
			current_user_grid.node_picture_url = grid_list[i].get('pictureUrl', 'No picture given')
			current_user_grid.node_public_url = grid_list[i].get('publicProfileUrl', '#')
			current_user_grid.connectors.add(current_user)

			k = 0
			if grid_list[i]['positions']['_total'] > 0: # if there are more than 0 positions listed 
				while k < len(grid_list[i]['positions']['values']): # while k is less than the number of positions listed 
					if grid_list[i]['positions']['values'][k]['isCurrent'] == True: # if the position is currently active
						try: 
							company_object = Company.objects.filter(node_company=grid_list[i]['positions']['values'][k]['company'].get('name', 'No company specified'), node_title=grid_list[i]['positions']['values'][k].get('title', 'No title specified'))[0]
						except: # why does it crash when I say: except Company.DoesNotExist?
							company_object = Company.objects.create(node_company=grid_list[i]['positions']['values'][k]['company'].get('name', 'No company specified'), node_title=grid_list[i]['positions']['values'][k].get('title', 'No title specified'))

						current_user_grid.company_set.add(company_object)

					k += 1

			else: 
				company_object = Company.objects.get_or_create(node_company='No company specified', node_title='No title specified')
				current_user_grid.company_set.add(company_object[0])

			current_user_grid.save()

	return grid_list



def delete_change(current_user_grid_connection, company_list_temp):

	'''
	Delete extra rows -- any rows pertaining to companies and titles that have 
	been removed in member's profile. 

	This covers the use case of: "If company / title deleted, then delete row."
	'''

	current_user_grid_connection_companies = current_user_grid_connection.company_set.all()

	for company_object in current_user_grid_connection_companies:
		if company_object.node_company not in company_list_temp:
			current_user_grid_connection.company_set.remove(company_object)
		elif company_object.node_title not in company_list_temp[company_object.node_company]: 
			current_user_grid_connection.company_set.remove(company_object)



def add_change(grid_list_connection, current_user_grid_connection, company_list_temp):

	'''
	Insert new rows for newly added companies and titles.  

	This covers the use case of: "If new company / title added, create new row 
	and insert."
	'''

	k = 0
	if grid_list_connection['positions']['_total'] > 0: # if there are more than 0 positions listed 
		while k < len(grid_list_connection['positions']['values']): # while k is less than the number of positions listed 
			if grid_list_connection['positions']['values'][k]['isCurrent'] == True: # if the position is currently active
				if not current_user_grid_connection.company_set.filter(
					node_company=grid_list_connection['positions']['values'][k]['company']['name'], 
					node_title=grid_list_connection['positions']['values'][k]['title']).exists(): # if company name in newly downloaded user's grid is not in the DB list of company names...

					# ... then create a new company object, add it to the grid member pulled from the DB (current_user_grid_connection) that corresponds to the grid member from the newly downloaded user's grid (grid_list)
					company_object = Company.objects.create(node_company=grid_list_connection['positions']['values'][k]['company']['name'], 
						node_title=grid_list_connection['positions']['values'][k]['title'])
					current_user_grid_connection.company_set.add(company_object)
					current_user_grid_connection.save()


				# ...finally, build a dictionary structured as: {'company_name' : ['list', 'of', 'titles']} for use in step 2 (deletions)			
				if grid_list_connection['positions']['values'][k]['company']['name'] in company_list_temp: 
					company_list_temp[grid_list_connection['positions']['values'][k]['company']['name']].append(grid_list_connection['positions']['values'][k]['title'])
				else: 
					company_list_temp[grid_list_connection['positions']['values'][k]['company']['name']] = [grid_list_connection['positions']['values'][k]['title']]

			k += 1

	return company_list_temp



@login_required
def sync(request):

	'''
	This function: 

	1. Checks whether each grid member in the logged in user's grid already exists in 
	DB. If not, save each new grid member to DB. 

	2. Takes the grid_list object downloaded from LinkedIn API and syncs to ensure 
	company and job title data is up to date reflecting any changes the grid member 
	may have made between logins of the logged in user. 

	Test cases: 
		1. user has no positions, then has 1
		2. user has no positions, then has 2
		3. user changes position, but has same number
		4. user has 2 positions, then reduces to 1
		5. user has 1 position, then reduces to 0

	'''

	# updates DB with any new grid members of the logged in user 
	grid_list = update_grid_to_DB(request)

	# stores any grid objects connected to the logged in user into a variable for momentary processing 
	current_user_grid = Grid.objects.filter(connectors=request.user)

	# for each item in the grid_list...
	for grid_list_connection in grid_list: 

		# ...fetch that person from the DB-stored grid
		current_user_grid_connection = current_user_grid.get(node_mid=grid_list_connection['id'])
		
		company_list_temp = {}

		# ...add any newly added companies to the member's company_set
		company_list_temp = add_change(grid_list_connection, current_user_grid_connection, company_list_temp)

		# ...remove any changed companies / titles from the member's company_set (does not delete from DB)
		delete_change(current_user_grid_connection, company_list_temp)

	# Redirect to rendered page
	get_request = request.session.get('gid', False)

	if get_request:
		return HttpResponseRedirect(reverse('group_pk', 
			kwargs={'group_pk' : get_request, }
		))
	else: 
		return HttpResponseRedirect('/home/group/')



def display_group(default_group_name, group_pk, current_user):

	'''
	If user selected to view one of his groups, then get that group and show it 
	(through the variable show_this_group). Otherwise, if the user didn't select
	a group, then default view the user's own default group: My own connections 
	for... If even that doesn't exist, then create it and add it to user's groups. 
	'''

	if group_pk != None: # if user clicked on existing group, switch to that group's view
		show_this_group = current_user.groups.get(id=group_pk)
	else: # on initial load, load default group
		try: # see if that group exists 
			show_this_group = current_user.groups.get(name=default_group_name)
		except Group.DoesNotExist: # if not, create it 
			try:
				show_this_group = current_user.groups.add(Group.objects.get(name=default_group_name))
			except Group.DoesNotExist:
				show_this_group = current_user.groups.create(name=default_group_name)
				current_user.save()

	return show_this_group



def select_group(request, group_pk, current_user):

	'''
	This logic controls which grid members to display based on whether and what 
	group is selected. 
	
	If no group is selected, group_pk == None, and the page is likely being loaded 
	on first login. In this case, show the user's own network as the logon default. 

	If the user clicks an existing group, then determine whether the group clicked 
	is the user's own default "my own connections" group. If it is, then again simply
	show the user's own network. 

	However, if the user selects any other group, then first identify all members of
	that group. Take those members and iterate through them one by one. For each 
	member, iterate in turn through each their grid_sets. If each grid item isn't 
	already in the accumulator called "current_user_grid," AND if the grid item is NOT
	the logged in user himself, AND if the current_user is not one of the connectors 
	(hence is a 2nd degree not 1st degree connection), then accumulate that grid item 
	into the accumulator dictionary called current_user_grid. Also add one to the 
	integer accumulator called grid_list_range. Finally, increment the counter "i" 
	by 1. 
	'''

	current_user_grid = []
	grid_list_range = []

	try: 
		del request.session['current_user_industries']
	except KeyError: 
		pass

	try: 
		del request.session['current_user_companies']
	except KeyError: 
		pass


	if group_pk == None: 
		u = User.objects.get(username=current_user.username)
		current_user_grid = u.grid_set.all()
		# u_grid_set = u.grid_set.all()
		# for person in u_grid_set:
		# 	current_user_grid.append(person)
		grid_list_range = range(len(u.grid_set.all()))
	else: 
		selected_group = Group.objects.get(id=group_pk)

		if selected_group.name == '%s %s\'s 1st degree connections' % (current_user.first_name, current_user.last_name): 
			current_user_grid = current_user.grid_set.all()
			# current_user_grid_set = current_user.grid_set.all()
			# for person in current_user_grid_set:
			# 	current_user_grid.append(person)
			grid_list_range = range(len(current_user.grid_set.all()))

			try: 
				del request.session['invite_others_to_group']
			except KeyError: 
				pass

		else: 

			current_user_grid_set = current_user.grid_set.all()

			request.session['invite_others_to_group'] = InviteOthersToGroup()

			# grab all users of the selected group 
			selected_group_users = selected_group.user_set.all().prefetch_related('grid_set')
			i = 0

			# for each user in that group...
			for u in selected_group_users: 

				# pull out that user's grid...
				grid_set_for_u = u.grid_set.all().prefetch_related('connectors')

				# then iterate through each of those grid items...
				for grid_item in grid_set_for_u: 

					connectors_for_grid_item = grid_item.connectors.all()

					'''
					Three conditions: 
					(1) if the grid_item hasn't already been captured in the 
					accumulator list, 
					(2) AND if the grid_item is NOT the current_user himself, 
					(3) AND if current_user is NOT one of the connectors of this 
					particular grid item (which means this grid_item is NOT a 1st degree 
					connection of current_user)
					(4) the grid item is not in current_user's grid - bc why would you need an intro to someone you already know? 
					'''

					if (grid_item not in current_user_grid) and (grid_item.node_mid != current_user.username) and (current_user not in connectors_for_grid_item) and (grid_item not in current_user_grid_set): 

						# for each connector in this grid item...
						for c in connectors_for_grid_item: 
							# ...if that connector is connected in the 1st degree to the current_user by virtue of being in his core grid_set, then append to the accumulator. 
							# if current_user.grid_set.filter(node_mid=c.username).exists(): 
							# add this grid item to the dictionary accumulator 
							current_user_grid.append(grid_item)
							grid_list_range.append(i)
							i += 1
							'''
							We break here because once a single connector is connected 
							to the logged in user, thereby making this grid item 
							a 2nd deg connection, there is no need to further 
							check other connectors, since it only takes one to 
							make the grid item a 2nd deg connection to the logged 
							in user. 
							'''
							break

	return current_user_grid, grid_list_range



@login_required
def group(request, group_pk=None):

	'''
	1. Builds accumulator of grid items to show depending on which group was 
	clicked by logged in user. 

	2. Captures string of clicked on group to display. 

	3. Saves variables to session cookies. 

	4. Redirects to /company view. 
	'''

	# Initialize variables
	current_user = request.user # current_user HERE
	default_group_name = '%s %s\'s 1st degree connections' % (current_user.first_name, current_user.last_name)
	
	# Build grid item accumulators based on which group link was clicked by logged in user. 
	current_user_grid, grid_list_range = select_group(request, group_pk, current_user)

	# Display selected group if one is selected, else display default group; save to variable 'show_this_group'
	show_this_group = display_group(default_group_name, group_pk, current_user)

	# Order all current_user's groups into a list.
	all_groups = current_user.groups.all().order_by('name')


	request.session['current_user_grid'] = current_user_grid
	request.session['grid_list_range'] = grid_list_range
	request.session['show_this_group'] = show_this_group
	request.session['all_groups'] = all_groups
	request.session['group_pk'] = group_pk

	view_filter = request.session.get('view_filter', '/company/')	

	return HttpResponseRedirect(view_filter)



@login_required
def company(request, sort_filter=None, view_filter='/company/'): 

	'''
	Allows sorting based on company if selected, or default if initial log in. 
	'''

	# grab latest current_user_grid from session cookie. 
	current_user_grid = request.session['current_user_grid']

	if 'current_user_companies' not in request.session: 

		current_user_companies = []

		for person in current_user_grid:
			company_set = person.company_set.all()
			for company in company_set:
				if company.node_company not in current_user_companies: 
					current_user_companies.append(company.node_company)
		
		# sort current_user_grid on company axis
		current_user_companies.sort()

		''' 
		This prevents django from bombing when user views an empty group, causing 
		Django to think current_user_companies is empty, and therefore switching to 
		the "else" in the template, causing industry to render instead (which would 
		also be empty if current_user_companies is empty)
		'''
		if not current_user_companies: 
			current_user_companies = ['So sad. You\'re the only one in this group. Invite people to see who they know! (Use the email box above.) ']

		request.session['current_user_companies'] = current_user_companies

	# store sort_filter, view_filter, and current_user_grid into session cookies 
	request.session['sort_filter'] = sort_filter
	request.session['view_filter'] = view_filter
	request.session['current_user_grid'] = current_user_grid

	try: 
		del request.session['current_user_industries']
	except KeyError: 
		pass

	return HttpResponseRedirect('/home')


@login_required
def industry(request, sort_filter=None, view_filter='/industry/'):

	'''
	Allows sorting based on industry if selected. 
	'''

	# grab latest current_user_grid from session cookie. 
	current_user_grid = request.session['current_user_grid']

	if 'current_user_industries' not in request.session: 

		current_user_industries = []

		for person in current_user_grid:
			if person.node_industry not in current_user_industries: 
				current_user_industries.append(person.node_industry)
		
		# sort current_user_grid on company axis
		current_user_industries.sort()

		''' 
		This mirrors the "empty" user feedback from the company() view.
		'''
		if not current_user_industries: 
			current_user_industries = ['So sad. You\'re the only member in this group. Invite people (using the email box above) to see who they know!']


		request.session['current_user_industries'] = current_user_industries

	# store sort_filter, view_filter, and current_user_grid into session cookies 
	request.session['sort_filter'] = sort_filter
	request.session['view_filter'] = view_filter
	request.session['current_user_grid'] = current_user_grid
	
	try: 
		del request.session['current_user_companies']
	except KeyError: 
		pass

	return HttpResponseRedirect('/home')


@login_required
def email(request): 

	'''
	1. Remember referral path in order to redirect back to it. 

	2. Render email form with POST data. 

	3. If email form after POST is valid, then clean the email string. If email is  
	already associated with a user, then render error message (by storing error 
	message in session cookie). Else, save that email address to DB as the user's 
	newly updated email address. Update default group by removing user from old group
	and creating new group if needed, then adding user to that group. 

	4. Save the email_form to session cookie, and redirect back to the redirect path. 
	'''

	# Stores most recent path into session cookie, and tees up as the redirect path. 
	request.session['last_path'] = request.session.get('path', '/home')
	redirect_path = request.session['last_path']

	# Render email form template and include email address located in POST data if it exists 
	email_form = EmailUpdate(request.POST)

	if email_form.is_valid():
		cd = email_form.cleaned_data
		user = request.user
		try: 
			# see if that email is already associated with an existing user 
			User.objects.get(email=cd['email'])
			# if so, then render an error message 
			request.session['user_notification'] = 'That email address already belongs to an IntroKick user.'
		except User.DoesNotExist:
			# if not, then save it as the user's new email address 
			if cd['email'] == '':
				request.session['user_notification'] = 'You didn\'t enter an email address.'
			else: 
				group_to_update = Group.objects.get(name='%s %s\'s 1st degree connections' % (user.first_name, user.last_name))
				user.email = cd['email']
				user.save()
				request.session['email_form'] = email_form
				group_to_update.name = '%s %s\'s 1st degree connections' % (user.first_name, user.last_name)
				group_to_update.save(update_fields=['name'])			

	else: 
		request.session['email_form'] = email_form

	return HttpResponseRedirect(redirect_path)



def group_typeahead(request):

	'''
	Implements bootstrap-based javastrict typeahead. 
	'''

	group_typeahead = []

	typeahead_list = Group.objects.all().exclude(name__endswith='\'s 1st degree connections')

	current_user = request.user

	for group in typeahead_list:
		if not group.name == '%s %s\'s 1st degree connections' % (current_user.first_name, current_user.last_name): 
			group_typeahead.append(group.name)

	group_typeahead = json.dumps(group_typeahead)

	return group_typeahead



def get_or_create_group(request, current_user):

	'''
	When user types a group name in the add / join field, either get or create 
	the group depending on whether it already exists. 
	'''

	try: # ...try to find the group the user typed, else if not found then create it
		show_this_group = Group.objects.get(name=request.POST['group'])
		group_members = show_this_group.user_set.all()
		return show_this_group, group_members
	except Group.DoesNotExist:
		show_this_group = current_user.groups.create(name=request.POST['group'])
		group_members = show_this_group.user_set.all()
		request.session['user_notification'] = 'You\'ve created the group: %s' % show_this_group
		return show_this_group, group_members
		return HttpResponseRedirect('/home/')
		


def list_group_members(group_members):

	''' 
	Iterates and creates a list of dictionary objects corresponding to each member 
	of the group.
	'''

	group_member_list = []
	i = 0

	for member in group_members: 
		group_member_list.append({})
		group_member_list[i]['first_name'] = member.first_name
		group_member_list[i]['last_name'] = member.last_name
		group_member_list[i]['picture_url'] = member.userprofile.user_picture_url
		group_member_list[i]['public_url'] = member.userprofile.user_url
		i += 1

	return group_member_list



@login_required
def add(request):

	'''
	This gives user option to request access to an existing group, or creates a new 
	group if it doesn't yet exist. 
	'''

	current_user = request.user # current_user HERE

	# Create user's ID variables
	first_name = current_user.first_name
	last_name = current_user.last_name
	email = request.session.get('email', current_user.email)
	
	# Create display variables from session cookies 
	show_this_group = request.session.get('show_this_group', '')
	all_groups = request.session.get('all_groups', '')
	control_group = all_groups.get(name='%s %s\'s 1st degree connections' % (current_user.first_name, current_user.last_name))
	group_member_list = request.session.get('group_member_list', '')
	# try: 
	# 	del request.session['group_member_list']
	# except KeyError: 
	# 	pass

	# extract and delete email_form session cookie 
	email_form = request.session.get('email_form', EmailUpdate(initial={'email' : request.user.email}))
	try: 
		del request.session['email_form']
	except KeyError: 
		pass

	# capture the creation of the GroupUpdate form into the session to be transported over to the home view for use there 
	request.session['group_form'] = GroupUpdate(request.POST)
	group_form = request.session.get('group_form', '')

	# This doesn't need to be captured into the session because the JoinGroup form will only be used in this view, and no others 
	group_member_form = True
	group_members = request.session.get('group_members', False)
	if group_members != False: 
		if current_user in group_members:
			group_member_form = False

	# refresh the current path into the session, because if e-mail is updated while in this view, you need to re-render this view, not the home view 
	request.session['path'] = request.path

	# Capture error message from request_access view if user did not select anyone to request e-mail invitation from 
	group_member_form_notification = request.session.get('group_member_form_notification', '')
	try: 
		del request.session['group_member_form_notification']
	except KeyError: 
		pass
	
	onload_modal = request.session.get('onload_modal', '')
	checkout_form = subscribe_paypal(request, current_user.username)

	# implement search typeahead
	typeahead_list = group_typeahead(request)

	# implement virality invite forms 
	invite_others_to_group = InviteOthersToGroup()
	invite_others = InviteOthers()


	'''
	Captures what the user typed, and split logic according to whether group 
	already exists.

	'''

	# If user pressed submit, and didn't send either an empty field or "Add or join a group," then...
	if ('group' in request.POST) and (request.POST['group'] != '' ) and (request.POST['group'] != 'Add or join a group'): 

		# ...get or create the group 
		show_this_group, group_members = get_or_create_group(request, current_user)

		# ...build the list of members in that group 
		group_member_list = list_group_members(group_members)

		# Capture the selected group and list of members of that group into the session to use in other views 
		request.session['show_this_group'] = show_this_group
		request.session['group_member_list'] = group_member_list

		# group_member_form = True 
		# request.session['group_member_form'] = group_member_form

		# If current_user is one of the group members, then do not show checkboxes or request to join e-mail option 
		request.session['group_members'] = group_members
		if current_user in group_members:
			group_member_form = False

	elif ('group' in request.POST) and ((request.POST['group'] == '' ) or (request.POST['group'] == 'Add or join a group')): 

		group_member_form_notification = 'Please enter a group name.'

		# return HttpResponse('error' + ";" + group_member_form_notification, content_type="text/plain")

	# if user refreshed the page by blank submitting group member to request access from, which caused a re-POST of "join group" with blank fields, then only render the blank submit error notification 
	# elif show_this_group != '' and group_member_list != '': 
	# elif ('group_members' not in request.POST):

	# 	group_member_form_notification = group_member_form_notification
	

	# extract and delete user_notification session cookie 
	user_notification = request.session.get('user_notification', '')
	try: 
		del request.session['user_notification']
	except KeyError: 
		pass


	return render_to_response('introkick/group.html', 
		{'current_user' : "Connections for %s %s" % (first_name, last_name), 
		'first_name' : first_name,
		'last_name' : last_name,
		# 'error_message_email' : error_message_email,
		'email' : email,
		'db_email' : current_user.email,
		'current_group' : show_this_group,
		'all_groups' : all_groups.all(),
		'control_group' : control_group,
		'group_member_list' : group_member_list,
		'group_member_list_range' : range(len(group_member_list)),
		'email_form' : email_form,
		'group_form' : group_form,
		'group_member_form' : group_member_form,
		'user_notification' : user_notification,
		'group_member_form_notification' : group_member_form_notification,
		'invite_others_to_group' : invite_others_to_group,
		'invite_others' : invite_others,
		'typeahead_list' : typeahead_list,
		'onload_modal' : onload_modal,
		'checkout_form' : checkout_form.sandbox(),
		}, 
		context_instance=RequestContext(request))



@login_required
def remove(request, group_pk=None):

	'''
	Remove user from a group when user clicks to leave group. 
	'''

	current_user = request.user # current_user HERE

	# Remove the group 
	group_to_remove = Group.objects.get(id=group_pk)
	
	if group_to_remove != Group.objects.get(name='%s %s\'s 1st degree connections' % (current_user.first_name, current_user.last_name)):
		current_user.groups.remove(Group.objects.get(id=group_pk))


	# If there are no more users in the group (this user turned out the lights), then delete the group itself 
	if not Group.objects.get(id=group_pk).user_set.all():
		Group.objects.get(id=group_pk).delete()

	default_group_name = '%s %s\'s 1st degree connections' % (current_user.first_name, current_user.last_name)

	# if user deleted the group he was currently viewing, then re-render the page to his default group: 'My own connections for'
	if request.session['group_pk'] == group_pk: 
		return HttpResponseRedirect(reverse('group_pk', 
			kwargs={'group_pk' : Group.objects.get(name=default_group_name).id, }
		))
	# else, re-render the same group's view in the homepage 
	else: 
		return HttpResponseRedirect('/home')



def send_email(subject, body, from_address, to_address=None, bcc_address=None):

	'''
	Send e-mail notifications. 
	'''

	message = EmailMessage(
		subject, 
		body, 
		from_address, 
		to_address, 
		bcc_address
	)

	message.send()



def invite_count(user_object):

	''' Add 1 to request invite count '''

	mid = get_or_create_mid(user_object.username)
	mid.invite_count += 1
	mid.save()



@login_required
def request_access(request, requester=None):

	'''
	User selects members of group from whom to request admission, dispatches request email to them. 
	'''
	
	# if user selected no one, then re-render page with error message
	if 'group_member' not in request.POST: 
		request.session['group_member_form_notification'] = 'Pick someone to request access to the group.'
		# group_member_form_notification = 'Pick someone to request access to the group.'
		# return HttpResponse(group_member_form_notification, content_type="text/plain")
		return HttpResponseRedirect('/home/group/add/')

	# build e-mail contents: requester's name, e-mail, mid, group she is seeking admission to + its group_pk, and selected person's e-mails
	else: 
		show_this_group = request.session['show_this_group']
		try: 
			del request.session['show_this_group']
		except KeyError: 
			pass

		requester = User.objects.get(username=requester)
		requester_name = '%s %s' % (requester.first_name, requester.last_name)
		requester_email = requester.email
		requester_username = requester.username
		requested_group_object = Group.objects.get(name=show_this_group)
		requested_group_pk = requested_group_object.id

		embed_url = 'http://' + request.get_host() + '/grant/' + str(requested_group_pk) + '/' + str(requester_username) + '/'

		# Pull out everyone whom user selected from request.POST, initialize recipient_emails variable to store their e-mails
		group_members = request.POST.getlist('group_member')
		group_members_range = range(len(group_members))
		bcc_address = []

		# Retrieve their e-mails using their LinkedIn public profile URL as the retrieval "hook"
		for index in group_members_range: 
			selected_userprofile = UserProfile.objects.get(user_url=group_members[index])
			bcc_address.append(selected_userprofile.user.email)

		# Send e-mail out
		subject = 'Approve access for %s to join the group "%s" on IntroKick?' % (requester_name, requested_group_object)
		body = 'Hi! \n\n%s (%s) is requesting to join the group "%s" on IntroKick. Click here to approve access for %s: %s. \n\nIf you don\'t know %s or don\'t want to approve access, just ignore this email. \n\nThanks for using IntroKick! \n\n\n- The IntroKick Team' % (requester_name, requester_email, requested_group_object, requester.first_name, embed_url, requester.first_name)
		from_address = 'IntroKick Notifications <archimedes@careerhoot.com>'
		to_address = []
		message = send_email(subject, body, from_address, to_address, bcc_address)

		invite_count(requester)

		request.session['user_notification'] = 'Your e-mail request to join %s was sent!' % requested_group_object

		# user_notification = 'Your e-mail request to join %s was sent!' % requested_group_object
		# return HttpResponse(user_notification, content_type="text/plain")


	return HttpResponseRedirect('/home')


def grant_access(request, group_pk=None, requester=None):

	'''
	Handles granting of group access to approver. 
	'''

	requester_user = User.objects.get(username=requester)
	requested_group_object = Group.objects.get(id=group_pk)

	try: 
		requester_mid = InviteMid.objects.get(mid=requester_user.username)
	except InviteMid.DoesNotExist:
		grant_access_notification = 'Oh, snap. We\'re sorry, but it doesn\'t look like %s %s requested to join the group "%s."' % (requester_user.first_name, requester_user.last_name, requested_group_object)
	else: 
		# if grantee is found with positive invite count in Mid table and isn't already a member of the group, then add to group and deduct from invite count 
		if (requester_mid.invite_count > 0) and (requester_user not in Group.objects.get(id=group_pk).user_set.all()):
			requester_user.groups.add(Group.objects.get(id=group_pk))
			requester_user.save()	
		
			requester_mid.invite_count -= 1
			requester_mid.save()

			sign_in_url = 'http://' + request.get_host() + '?gid=' + str(group_pk)

			# send confirmation email to grantee 
			subject = 'Your request to join the group "%s" has been approved' % requested_group_object
			body = '%s, \n\nYour request to join the group "%s" on IntroKick has been approved! Awesome! \n\nClick here (%s) to login now and check out your IntroKick connections in the %s group. \n\nThanks for using IntroKick! \n\n\n-The IntroKick Team' % (requester_user.first_name, requested_group_object, sign_in_url, requested_group_object)
			from_address = 'IntroKick Notifications <archimedes@careerhoot.com>'
			to_address = [requester_user.email]
			message = send_email(subject, body, from_address, to_address)

			# show confirmation to grantor 
			grant_access_notification = 'Thanks for approving access for %s %s to the group "%s"!' % (requester_user.first_name, requester_user.last_name, requested_group_object)
		# show error notification to grantor 
		else: 
			grant_access_notification = 'We\'re sorry, but %s %s is either already in the group "%s," or hasn\'t asked to join the group yet.' % (requester_user.first_name, requester_user.last_name, requested_group_object)

	return render_to_response('introkick/grant.html', 
		{'grant_access_notification' : grant_access_notification,
		}, 
		context_instance=RequestContext(request))



@login_required
def invite_to_group(request):

	'''
	Handles logic for when a user tries to invite someone to a group. 
	'''

	target_group = request.session.get('show_this_group', '')

	invite_others_to_group = InviteOthersToGroup(request.POST)

	if invite_others_to_group.is_valid():

		cd = invite_others_to_group.cleaned_data
		user = request.user
		sign_in_url = 'http://' + request.get_host() + '?gid=' + str(target_group.id)

		try: 
			# see if that email is already associated with an existing user 
			target_user = User.objects.get(email=cd['email'])
			body = '%s, \n\n%s %s (%s) invited you to join the group "%s" on IntroKick, the easiest tool for getting warm intros to the professionals you want to meet -- from people you already know. \n\nClick here (%s) to login in directly with LinkedIn (no registration required) and check out your IntroKick connections in the %s group. \n\nEnjoy using IntroKick! \n\n\n-The IntroKick Team' % (target_user.first_name, user.first_name, user.last_name, user.email, target_group.name, sign_in_url, target_group.name)
		except User.DoesNotExist:
			# if not, then save it as the user's new email address 
			target_user = None
			body = 'Hi! \n\n%s %s (%s) has invited you to join the group "%s" on IntroKick, the easiest tool for getting warm introductions to the professionals you want to meet -- from people you already know. \n\nClick here (%s) to login in directly with LinkedIn (no registration required) and check out your IntroKick connections in the %s group. \n\nWe hope you enjoy using IntroKick! \n\n\n-The IntroKick Team' % (user.first_name, user.last_name, user.email, target_group.name, sign_in_url, target_group.name)


		'''
		Handling logic below. 
		'''

		# if user isn't a member of the group...
		if user not in target_group.user_set.all(): 

			user_notification = 'Unfortunately, you must be a member of the group %s first before you can invite others.' % target_group.name

		# if grantee is already a member of the group...
		elif target_user in target_group.user_set.all(): 

			user_notification = 'It looks like that person is already a member of the group %s.' % target_group.name

		# if user is attempting to invite himself 
		elif cd['email'] == user.email: 

			user_notification = 'It appears you are inviting yourself to the group %s, which unfortunately isn\'t allowed.' % target_group.name

		# if user is submitting the default email example address 
		elif cd['email'] == 'name@example.com' or cd['email'] == '': 

			user_notification = 'Please enter an actual e-mail address.'

		else: 

			# if user is already an IntroKick user, then add to his invite count 
			if target_user: 
				invite_count(target_user)

			# send invite notification to grantee 
			subject = '%s %s wants you to meet awesome people in the group "%s" on IntroKick' % (user.first_name, user.last_name, target_group.name)
			from_address = 'IntroKick Notifications <archimedes@careerhoot.com>'
			to_address = [cd['email']]
			message = send_email(subject, body, from_address, to_address)

			# render confirmation banner notification to inviter 
			user_notification = 'Thanks for sending a group invitation to %s!' % cd['email']


	request.session['invite_others_to_group'] = invite_others_to_group
	request.session['user_notification'] = user_notification

	# user_notification_dict = {
	# 	'flag' : user_notification_flag, 
	#  	'notification' : user_notification
	#  }

	# content_type="text/plain"
	# mimetype="application/json"
	# return HttpResponse(user_notification, content_type="text/plain")
	return HttpResponseRedirect('/home/')



@login_required
def invite(request):

	'''
	THIS VIEW IS NOT IN USE. 
	Handles logic for inviting new users to the IntroKick service. 
	'''

	request.session['last_path'] = request.session.get('path', '/home')
	redirect_path = request.session['last_path']

	invite_others = InviteOthers(request.POST)

	if invite_others.is_valid():

		cd = invite_others.cleaned_data
		user = request.user

		try: 
			# see if that email is already associated with an existing user 
			target_user = User.objects.get(email=cd['email'])
		except User.DoesNotExist:
			# if not, then save it as the user's new email address 
			target_user = None


		'''
		Handling logic below. 
		'''

		# if user typed his own email address...
		if cd['email'] == user.email: 
			request.session['user_notification'] = 'You entered your own e-mail address. Did you mean to invite yourself?'

		# if user submitted the default example email address...
		elif cd['email'] == 'name@example.com' or cd['email'] == '': 
			request.session['user_notification'] = 'Please enter an actual e-mail address.'

		else: 
			# send email to invtee 
			sign_in_url = 'http://' + request.get_host() + '/'
			subject = 'Invitation to IntroKick'
			body = '%s %s (%s) has invited you to join IntroKick, a micro-network to make professional introductions easier! Click here (%s) to sign in with LinkedIn and start kicking off intros!' % (user.first_name, user.last_name, user.email, sign_in_url)
			from_address = 'IntroKick Notifications <archimedes@careerhoot.com>'
			to_address = [cd['email']]
			message = send_email(subject, body, from_address, to_address)

			# render confirmation banner notification to inviter 
			request.session['user_notification'] = 'Thanks for sending an invitation to %s!' % target_email
	

	request.session['invite_others'] = invite_others

	return HttpResponseRedirect(redirect_path)


def grid_light(i, g, grid, current_user_grid_set, company, filter_lens):

	'''
	Show grid companies / industries on iniital load. 
	'''
	
	grid.append(dict())

	if filter_lens == 'industry': 
		grid[i]['title'] = ', '.join(company.values_list('node_title', flat=True))
		grid[i]['company'] = ', '.join(company.values_list('node_company', flat=True))
	elif filter_lens == 'company': 
		grid[i]['title'] = company.node_title
		grid[i]['company'] = company.node_company

	return grid



def create_grid_dictionaries(i, g, grid, current_user_grid_set, company, filter_lens):

	'''
	Create grid dictionaries from current user's grid data. 
	'''
	
	grid.append(dict())
	grid[i]['mid'] = g.node_mid
	grid[i]['first_name'] = g.node_first_name
	grid[i]['last_name'] = g.node_last_name
	grid[i]['location'] = g.node_location
	grid[i]['industry'] = g.node_industry
	grid[i]['picture_url'] = g.node_picture_url
	grid[i]['public_url'] = g.node_public_url

	if filter_lens == 'industry': 
		grid[i]['title'] = ', '.join(company.values_list('node_title', flat=True))
		grid[i]['company'] = ', '.join(company.values_list('node_company', flat=True))
	elif filter_lens == 'company': 
		grid[i]['title'] = company.node_title
		grid[i]['company'] = company.node_company

	grid[i]['connectors'] = []
	grid[i]['connector_urls'] = []

	g_connectors = g.connectors.all()

	for c in g_connectors: 
		# if this particular connector is in the current_user's grid, then this connector is a 1st degree connection and we want to include him 
		# if current_user_grid_set.filter(node_mid=c.username).exists():
		grid[i]['connectors'].append("%s %s" % (c.first_name, c.last_name))
		grid[i]['connector_urls'].append(c.userprofile.user_url)

	return grid


@login_required
def ajax(request): 

	'''
	This function processes a client-side Ajax request by rendering dynamically 
	the people results based on a user clicking on a specific company or industry. 

	2 places to grab LinkedIn anonymous images: 

	http://www.vdvl.nl/wp-content/uploads/2012/10/icon_no_photo_no_border_80x80.png
	http://s.c.lnkd.licdn.com/scds/common/u/images/themes/katy/ghosts/person/ghost_person_60x60_v1.png

	Spinners: 
	{{ STATIC_URL }}images/spinner.gif
	http://spicypickle.orders24-7.com/images/map_spinner.gif
	http://www.easel.ly/jquery/images/spinner.gif
	http://www.kingsleybate.com/images/loading-spinner.gif
	http://cdn.css-tricks.com/wp-content/uploads/2011/02/spinnnnnn.gif

	<script type='text/javascript' src='http://malsup.github.com/jquery.form.js'></script>
	https://raw.github.com/needim/noty/master/js/noty/jquery.noty.js
	https://raw.github.com/needim/noty/master/js/noty/layouts/bottom.js
	https://raw.github.com/needim/noty/master/js/noty/themes/default.js

	//netdna.bootstrapcdn.com/twitter-bootstrap/2.3.1/css/bootstrap-combined.min.css
	'''

	if not request.is_ajax():
		raise Http404
	else: 
		current_user = request.user
		current_user_grid = request.session['current_user_grid']
		current_user_grid_set = current_user.grid_set.all()

		try: 
			data = request.GET['company']
			data = urllib.unquote(data)
			expanded_company = Company.objects.filter(node_company=data)

			# create grid dictionaries to render in template 
			i = 0
			grid = []

			for company in expanded_company: 
				company_grid_members = company.grid.all()
				for g in company_grid_members:
					# this culls company_grid_members down to just those grid members who were assembled into current_user_grid from the function select_group()
					if g in current_user_grid: 
						filter_lens = 'company'
						grid = create_grid_dictionaries(i, g, grid, current_user_grid_set, company, filter_lens)
						i += 1

			data = json.dumps(grid)

		except:
			data = request.GET['industry']
			data = urllib.unquote(data)
			expanded_industry = Grid.objects.filter(node_industry=data)

			i = 0
			grid = []

			# create grid dictionaries to render in template 
			for each_person in expanded_industry: 
				# this culls expanded_industry members down to just those grid members who were assembled into current_user_grid from the function select_group()
				if each_person in current_user_grid: 
					filter_lens = 'industry'
					each_person_companies = each_person.company_set.all()
					grid = create_grid_dictionaries(i, each_person, grid, current_user_grid_set, each_person_companies, filter_lens)
					i += 1

			# code.interact(local=locals())
			data = json.dumps(grid)

		return HttpResponse(data, mimetype="application/json")



def subscribe_paypal(request, user_id):

	'''
	/usr/local/lib/python2.7/dist-packages/paypal
	'''

    # What you want the button to do.
	paypal_dict = {
		"cmd": "_xclick-subscriptions",
		"business": "archimedes-facilitator@careerhoot.com",
		"a3": "4.95",                      # monthly price 
		"p3": 1,                           # duration of each unit (depends on unit)
		"t3": "D",                         # duration unit ("M for Month")
		"src": "1",                        # make payments recur
		"sra": "1",                        # reattempt payment on payment error
		"no_note": "1",                    # remove extra notes (optional)
		"custom" : user_id,	# to ID the user when the IPN signal comes back
		"item_name": "IntroKick: 1-DAY recurring subscription",
		# "notify_url": "http://localhost:8000/introkick/paypal/ipn",
		# "return_url": "http://localhost:8000/introkick/paypal/pdt",
		"cancel_return": 'http://' + request.get_host() + '/home/group/',
	}

	# Create the instance.
	checkout_form = PayPalPaymentsForm(initial=paypal_dict, button_type="subscribe")
	return checkout_form
	# request.session['checkout_form'] = checkout_form



# @receiver(paypal_ipn_signal)
# def test_ipn(sender, **kwargs):
#     ipn_obj = sender
#     # Undertake some action depending upon `ipn_obj`.
#     if ipn_obj.custom:
#     	print ipn_obj.custom
        # Users.objects.update(paid=True)        

	# paypal_ipn_signal.connect(test_ipn)




def flip_first_entitlements(request, pdt_obj):

	'''
	Turn on entitlements if you've paid 
	WHAT IF PAID IS TRUE, BUT RECURRENCE HAS HAPPENED? NEED WAY TO PUSH OUT ANOTHER
	MONTH

	IF PAYMENT LAPSES, MAKE SURE TO FLIP PAID TO FALSE

	DO I GET THE SAME SIGNAL BACK FOR RECURRING CHARGE? NEED TO ASSOCIATE BUYER ID 
	WITH USERNAME

	CHANGE flip entitlements view to use CUSTOM field of PDT object, not 
	current_user - since user may bounce out of browser before being 
	redirected - grab CUSTOM field from PDT table, then lookup on User table
	'''

	if pdt_obj.st == 'SUCCESS': 

		current_user = UserProfile.objects.get(user=User.objects.get(username=pdt_obj.custom))
		
		if current_user.paid == False: 
			current_user.paid = True
		
		if timezone.now() <= current_user.subs_expiry: 
			current_user.subs_expiry = current_user.subs_expiry + relativedelta(months=1)		
		else: 
			current_user.subs_expiry = timezone.now() + relativedelta(months=1)

		current_user.save()
		request.session['onload_modal'] = 'paid'

		return current_user.subs_expiry, request.session['onload_modal']



def cancel_entitlements(request, current_user):

	if current_user.get_profile().paid == True: 
		current_user.get_profile().paid = False
		current_user.get_profile().subs_expiry = timezone.now()
		current_user.get_profile().save()



@login_required
def home(request):

	'''
	Renders the homepage after you log in. 

	CHECK FOR ENTITLEMENTS FIRST BEFORE PROCEEDING EVEN ALLOWING LOGIN AND SYNC, ELSE SEND TO 
	UPGRADE PAGE
	'''

	# Create user's ID variables
	current_user = request.user # current_user HERE
	
	first_name = current_user.first_name
	last_name = current_user.last_name
	email = request.session.get('email', current_user.email)
	current_user_grid_set = current_user.grid_set.all()

	# Create display variables from session cookies 
	request.session['path'] = request.path
	
	current_user_grid = request.session.get('current_user_grid', False)
	current_user_companies = request.session.get('current_user_companies', False)
	current_user_industries = request.session.get('current_user_industries', False)

	# grid_list_range = request.session['grid_list_range']
	show_this_group = request.session.get('show_this_group', '%s %s\'s 1st degree connections' % (first_name, last_name))
	all_groups = request.session.get('all_groups', current_user.groups.all().order_by('name'))
	control_group = all_groups.get(name='%s %s\'s 1st degree connections' % (current_user.first_name, current_user.last_name))
	group_pk = request.session.get('group_pk', False)
	sort_filter = request.session.get('sort_filter', False)
	invite_others = request.session.get('invite_others', InviteOthers(request.POST))

	# only show the viral email invite form if you are viewing a group that's not your default group 
	invite_others_to_group = request.session.get('invite_others_to_group', InviteOthersToGroup(request.POST))

	group_form = request.session.get('group_form', GroupUpdate())

	# extract and delete email_form session cookie 
	email_form = request.session.get('email_form', EmailUpdate(initial={'email' : request.user.email}))
	try: 
		del request.session['email_form']
	except KeyError: 
		pass

	# extract and delete user_notification session cookie 
	user_notification = request.session.get('user_notification', '')
	try: 
		del request.session['user_notification']
	except KeyError: 
		pass

	# extract and delete 14 day free trial session cookie 
	days_elapsed = request.session.get('days_elapsed', '')
	onload_modal = request.session.get('onload_modal', '')
	show_popup = request.session.get('show_popup', '')
	try: 
		del request.session['show_popup']
	except KeyError: 
		pass

	# extract expiration date
	# subs_expiry = request.session.get('subs_expiry', '')

	# implement group typeahead
	typeahead_list = group_typeahead(request)

	# PayPal checkout form
	checkout_form = subscribe_paypal(request, current_user.username)
	pdt_obj = request.session.get('pdt_obj', False)
	try: 
		del request.session['pdt_obj']
	except KeyError: 
		pass

	# success_string = False

	# Turn on entitlements if you've paid 
	if pdt_obj:

		# code.interact(local=locals())

		subs_expiry, onload_modal = flip_first_entitlements(request, pdt_obj)

		# If you're coming from PayPal, then show payment confirmation page 
		return render_to_response('introkick/paypal.html', 
			{'current_user' : "Connections for %s %s" % (first_name, last_name), 
			'first_name' : first_name,
			'last_name' : last_name,
			'email' : email,
			'db_email' : current_user.email,
			'current_group' : show_this_group,
			'all_groups' : all_groups.all(),
			'control_group' : control_group, 
			'invite_others_to_group' : invite_others_to_group, 
			'user_notification' : user_notification,
			'days_elapsed' : days_elapsed, 
			'onload_modal' : onload_modal,
			'typeahead_list' : typeahead_list,
			'checkout_form' : checkout_form,
			'pdt_obj' : pdt_obj, 
			# 'success_string' : success_string, 
			'subs_expiry' : subs_expiry.strftime("%A, %B %d, %Y"),
			}, 
			context_instance=RequestContext(request))

	else: 
		return render_to_response('introkick/home.html', 
			{'current_user' : "Connections for %s %s" % (first_name, last_name), 
			'first_name' : first_name,
			'last_name' : last_name,
			'email' : email,
			'db_email' : current_user.email,
			'current_user_industries' : current_user_industries, 
			'current_user_companies' : current_user_companies,		
			'current_group' : show_this_group,
			'all_groups' : all_groups.all(),
			'control_group' : control_group, 
			# 'sort_filter' : sort_filter,
			# 'invite_others' : invite_others, 
			'invite_others_to_group' : invite_others_to_group, 
			# 'group_form' : group_form,
			# 'email_form' : email_form,
			'user_notification' : user_notification,
			'days_elapsed' : days_elapsed, 
			'onload_modal' : onload_modal,
			'show_popup' : show_popup,
			'typeahead_list' : typeahead_list,
			'checkout_form' : checkout_form.sandbox(),
			'pdt_obj' : pdt_obj, 
			# 'success_string' : success_string, 
			}, 
			context_instance=RequestContext(request))
