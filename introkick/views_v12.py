# Create your views here.

# Import Python modules 
import oauth2 as oauth
import cgi
import simplejson as json
import datetime
import re
import urlparse 
import pprint
from MySQLdb import IntegrityError
from operator import itemgetter

# Import Django modules 
from django.shortcuts import render_to_response, get_object_or_404
from django.http import HttpResponseRedirect, HttpResponse
from django.conf import settings
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User, Group, AnonymousUser
from django.contrib.auth.decorators import login_required
from django.template import RequestContext
from django.core.urlresolvers import reverse
from django.core.mail import send_mail, EmailMessage

# Import Custom modules - not needed any longer since oauth credential sit in settings 
# import linkedin_core

# Import models 
from introkick.models import *

'''
This pulls in my oauth token and secret, which was generated from the LinkedIn 
developer portal. It also sets the request token, access token, and authentication 
URLs
'''

consumer = oauth.Consumer(settings.LINKEDIN_TOKEN, settings.LINKEDIN_SECRET)
client = oauth.Client(consumer)

request_token_url = 'https://api.linkedin.com/uas/oauth/requestToken?scope=r_network+r_emailaddress'
access_token_url = 'https://api.linkedin.com/uas/oauth/accessToken'
authenticate_url = 'https://www.linkedin.com/uas/oauth/authenticate'


'''
This is the login page. It simply shows a "login with LinkedIn" button.
'''

def index(request):
    return render_to_response('introkick/index.html', context_instance=RequestContext(request))


'''
This processes the oauth-based login. It creates an oauth callback URL, then makes the 
oauth call using that callback URL. It retrieves the oauth token. Then it creates and 
directs to a URL consisting of the authentication URL with the oauth token as a passed
parameter. 
'''

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


'''
This logs the user out. 

BUG FIX: need to figure out how to flush stored oauth credentials from IntroKick
cookie or session, or LinkedIn cookie or session. 
'''


# /oauth_logout
@login_required
def oauth_logout(request):
	# Log a user out using Django's logout function and redirect them back to the homepage.
	logout(request)

	# request.session.flush()
	# request.session.clear()
	# request.session['request_token'] = ''
	# del request.session['request_token']
	# for sesskey in request.session.keys():
	# 	del request.session[sesskey]
	# del request.session
	# request.session = ''
	# # request.session['HTTP_COOKIE']
	# # request.session['TERM_SESSION_ID']
	# request.user = AnonymousUser()
	# user = AnonymousUser()
	# access_token = ''
	# token = ''
	# client = ''
	# content = ''
	# settings.LINKEDIN_TOKEN = ''
	# request.META['HTTP_COOKIE'] = ''
	# request.COOKIES['sessionid'] = ''
	# assert False

	return HttpResponseRedirect('/introkick/')


'''
This completed oauth authentication by passing the oauth token and secret, along with
the oauth_verifier, back to LinkedIn, and LinkedIn send back the access_token. Using 
the access_token, we can then actually make API calls. 

Once authenticated, we call the basic profile service to figure out who the user is. 
We store the user's first and last name, email, and mid. We also try to store the user's 
picture URL and public profile URL, if publicly exposed. 

Then, we try to retrieve that user from the DB. If the user is not found in the DB, we
create a new user with those credentials. Lastly, we authenticate and login the user
into our IntroKick app, and redirect to /sync. If login failed for some reason, we
render an error message. 
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

	headers = {'x-li-format': 'json'}
	token = oauth.Token(access_token['oauth_token'], 
		access_token['oauth_token_secret'])
	client = oauth.Client(consumer, token)

	resp, user_temp = client.request("http://api.linkedin.com/v1/people/~:(id,picture-url,public-profile-url,first-name,last-name,email-address,location:(name),industry,positions:(title,company:(name),is-current))", 
		"GET", headers=headers)

	user_dict_temp = json.loads(user_temp)

	# Step 3. Create user attributes.
	first_name = user_dict_temp["firstName"]
	last_name = user_dict_temp["lastName"]
	email = user_dict_temp["emailAddress"]
	user_id = user_dict_temp["id"]
	user_picture_url = user_dict_temp.get('pictureUrl', 'No picture given')
	user_url = user_dict_temp.get('publicProfileUrl', '#')


	try:
		user = UserProfile.objects.get(user__username=user_id)
		user.login_count += 1
		user.save()
	except UserProfile.DoesNotExist:
		user = User.objects.create_user(
			username=user_id, 
			password=access_token['oauth_token_secret'])
		user.first_name = first_name
		user.last_name = last_name
		user.email = email
		user.date_joined = timezone.now()
		user.groups.create(name='My own connections for: %s' % user.email)
		user.save()

		userprofile = UserProfile()
		userprofile.user = user
		userprofile.oauth_token = access_token['oauth_token']
		userprofile.oauth_secret = access_token['oauth_token_secret']
		userprofile.login_count = 1
		userprofile.user_url = user_url
		userprofile.user_picture_url = user_picture_url
		userprofile.save()

	# Now, authenticate the user and log them in using Django's 
	# pre-built functions for these things. 
	user = authenticate(username=user_id, 
		password=access_token['oauth_token_secret'])
	if user: 
		login(request, user)
		return HttpResponseRedirect('/introkick/sync/')
	else: 
		return render_to_response('introkick/index.html', 
			{
			'first_name' : first_name, 
			'last_name' : last_name,
			'email' : email,
			'error_message' : "Um, login failed."
			})


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


# /
@login_required
def sync(request):

	# 1. Connect to LinkedIn API and pull signed in user's list of connections
	token = oauth.Token(request.user.get_profile().oauth_token, 
		request.user.get_profile().oauth_secret)
	client = oauth.Client(consumer, token)
	headers = {'x-li-format': 'json'}

	resp, grid_temp = client.request("http://api.linkedin.com/v1/people/~/connections:(id,picture-url,public-profile-url,first-name,last-name,location:(name),industry,positions:(title,company:(name),is-current))", 
		"GET", headers=headers)



	# 2. Manipulate response from LinkedIn API into list type
	grid_dict_temp = json.loads(grid_temp)

	grid_list = grid_dict_temp['values']



	# 3. Prune list to eliminate empty profiles where connection turned on privacy / visibility 
	temp_range_counter = []
	j = 0

	for i in range(len(grid_list)):
		if ('private' == grid_list[i]['lastName']):
			temp_range_counter.append(i)

	for i in range(len(temp_range_counter)):
		grid_list.pop(temp_range_counter[i]-j)
		j += 1


	# 4. Initialize all helper variables 
	grid_list_range = range(len(grid_list))
	mids = []
	grid_firstName = []
	grid_lastName = []
	grid_location = []
	grid_industry = []
	grid_companies = []
	grid_titles = []
	grid_picture_url = []
	grid_public_url = []

	# 5. Populate helper variables by parsing "super" list from LinkedIn API
	for i in grid_list_range:
		mids.append(grid_list[i].get('id', 'ID unspecified'))
		grid_firstName.append(grid_list[i].get('firstName', 'First name unspecified'))
		grid_lastName.append(grid_list[i].get('lastName', 'Last name unspecified'))
		grid_location.append(grid_list[i]['location'].get('name', 'Location unspecified'))
		grid_industry.append(grid_list[i].get('industry', 'Industry unspecified'))
		grid_picture_url.append(grid_list[i].get('pictureUrl', 'No picture given'))
		grid_public_url.append(grid_list[i].get('publicProfileUrl', '#'))


		# This loop is needed to populate company / title list for people who have multiple current positions 
		k = 0
		if grid_list[i]['positions']['_total'] > 0: # if there are more than 0 positions listed 
			while k < len(grid_list[i]['positions']['values']): # while k is less than the number if positions listed 
				if grid_list[i]['positions']['values'][k]['isCurrent'] == True: # if the position is currently active

					# load company list object 

					try: # check whether there is already a company object for this iteration 
						# grid_titles[i]
						grid_companies[i] 
					except IndexError: # if not, load a new company list object 
						try:
							# grid_titles.append([grid_list[i]['positions']['values'][k]['company']['name']])
							grid_companies.append([grid_list[i]['positions']['values'][k]['company']['name']])
						except KeyError: 
							# grid_titles.append(['No company specified'])
							grid_companies.append(['No company specified'])
					else: # otherwise append to the existing company list object 
						try:
							# grid_titles[i].append(grid_list[i]['positions']['values'][k]['company']['name'])
							grid_companies[i].append(grid_list[i]['positions']['values'][k]['company']['name'])
						except KeyError: 
							# grid_titles[i].append('No company specified')
							grid_companies[i].append('No company specified')

					# load title list object 

					try: # check whether there is already a title object for this iteration 
						grid_titles[i]
					except IndexError: # if not, load a new title list object 
						try: 
							grid_titles.append([grid_list[i]['positions']['values'][k]['title']])
						except KeyError: 
							grid_titles.append(['No title specified'])
					else: # otherwise append to the existing title list object 
						try: 
							grid_titles[i].append(grid_list[i]['positions']['values'][k]['title'])
						except KeyError: 
							grid_titles[i].append('No title specified')

				k += 1 # add 1 to k 

		else: 
			grid_titles.append(['No title specified'])
			grid_companies.append(['No company specified'])



	# 6. Write to DB
	
	for i in grid_list_range:
		try: # see if that mid exists 
			mid = Mid.objects.get(mid=mids[i])
		except(KeyError, Mid.DoesNotExist): # if not, create it 
			mid = Mid.objects.create(mid=mids[i])
			current_user_grid = Grid.objects.create(node_mid=mid)
			for company, title in zip(grid_companies[i], grid_titles[i]):
				current_user_grid.node_first_name = grid_firstName[i]
				current_user_grid.node_last_name = grid_lastName[i]
				current_user_grid.node_location = grid_location[i]
				current_user_grid.node_industry = grid_industry[i]
				current_user_grid.node_picture_url = grid_picture_url[i]
				current_user_grid.node_public_url = grid_public_url[i]
				current_user_grid.node_company = company
				current_user_grid.node_title = title
				current_user_grid.connectors.add(request.user)
				current_user_grid.save()
		else: # otherwise, use that mid to pull the associated grid 
			# try: # try to pull associated grid 

			'''
			Initialize temp vars for lists of companies, titles, and existing grid 
			rows for current member mid.
			'''

			company_list = grid_companies[i]
			title_list = grid_titles[i]
			current_user_grid = []
			for item in Grid.objects.filter(node_mid=mid): 
				current_user_grid.append(item)
			grid_member_connectors = Grid.objects.filter(node_mid=mid)[0].connectors.all()
			# except(KeyError, Grid.DoesNotExist): # if cannot, then create a new grid row and save
			# 	for company, index in zip(grid_companies[i], range(len(grid_companies[i]))):
			# 		current_user_grid = Grid.objects.create(node_mid=mid)
			# 		current_user_grid.node_first_name = grid_firstName[i]
			# 		current_user_grid.node_last_name = grid_lastName[i]
			# 		current_user_grid.node_location = grid_location[i]
			# 		current_user_grid.node_industry = grid_industry[i]
			# 		current_user_grid.node_picture_url = grid_picture_url[i]
			# 		current_user_grid.node_public_url = grid_public_url[i]
			# 		current_user_grid.node_company = company
			# 		current_user_grid.node_title = grid_titles[i][index]
			# 		current_user_grid.connectors.add(request.user)
			# 		current_user_grid.save()
			# else: # otherwise, check to make sure existing grid row is still up to date 

			'''
			1. Pop all companies, titles, and existing grid rows from initialized 
			lists if company and title already match the exsiting row in question.

			This covers the use case of "If no company or title change, do nothing."
			'''

			for grid_member in current_user_grid:
				for company, title in zip(company_list, title_list):
					try: 
						if (company == grid_member.node_company) and (title == grid_member.node_title):
							try: # make sure connectors column is up to date before popping off the row from current_user_grid
								grid_member.connectors.get(username=request.user.username)
							except(KeyError, User.DoesNotExist):
								grid_member.connectors.add(request.user)
								grid_member.save()
							current_user_grid.pop(current_user_grid.index(grid_member))
							company_list.pop(company_list.index(company))
							title_list.pop(title_list.index(title))
					except ValueError: 
						pass

			'''
			2. Delete all extra rows -- this deletes any rows pertaining to companies 
			and titles that have been removed in member's profile. 

			This covers the use case of: "If company / title deleted, then delete row."
			'''

			for grid_member in current_user_grid: 
				Grid.objects.get(id=grid_member.id).delete()


			'''
			3. Insert new rows for newly added companies and titles.  

			This covers the use case of: "If new company / title added, create new row 
			and insert."
			'''


			for company, title in zip(company_list, title_list):
				current_user_grid = Grid.objects.create(node_mid=mid)
				current_user_grid.node_first_name = grid_firstName[i]
				current_user_grid.node_last_name = grid_lastName[i]
				current_user_grid.node_location = grid_location[i]
				current_user_grid.node_industry = grid_industry[i]
				current_user_grid.node_picture_url = grid_picture_url[i]
				current_user_grid.node_public_url = grid_public_url[i]
				current_user_grid.node_company = company
				current_user_grid.node_title = title
				for connector in grid_member_connectors: 
					current_user_grid.connectors.add(connector)
				current_user_grid.connectors.add(request.user) # need to add all connectors, not just this one 
				current_user_grid.save()


		# cases
		# 1. user has no positions, then has 1
		# 2. user has no positions, then has 2
		# 3. user changes position, but has same number
		# 4. user has 2 positions, then reduces to 1
		# 5. user has 1 position, then reduces to 0



	# 7. Redirect to rendered page
	return HttpResponseRedirect('/introkick/home/group/')


@login_required
def group(request, group_pk=None, view_filter='/introkick/company/'): # 

	# Initialize variables
	current_user = request.user
	default_group_name = 'My own connections for: %s' % current_user.email
	grid_list_range = []
	current_user_grid = []


	'''
	This logic controls what to display based on whether and what group is selected. 
	
	If no group is selected, group_pk == None, and the page is likely being loaded 
	on first login. In this case, show the user's own network as the logon default. 

	If the user clicks an existing group, then determine whether the group clicked 
	is the user's own default "my own connections" group. If it is, then again simply
	show the user's own network. 

	However, if the user selects any other group, then first identify all members of
	that group. Take those members and iterate through them one by one. For member, 
	iterate in turn through each row of their grid. If that row isn't already in 
	the accumulator called "current_user_grid" AND if the current_user is not one of
	the connectors (hence is a 2nd degree not 1st degree connection), then accumulate
	that grid row into the accumulator called current_user_grid. Also add one to the
	integer accumulator called grid_list_range. Finally, increment the counter "i" by
	1. 

	'''

	if group_pk == None: 
		u = User.objects.get(username=request.user.username)
		current_user_grid = u.grid_set.all()
		grid_list_range = range(len(u.grid_set.all()))

		# for item in u.grid_set.all(): 
		# 	# if current_user not in item.connectors.all():
				# current_user_grid.append(item)
				# grid_list_range.append(i)
				# i += 1
	else: 
		selected_group = Group.objects.get(id=group_pk)

		if selected_group.name == 'My own connections for: %s' % current_user.email: 
			current_user_grid = current_user.grid_set.all()
			grid_list_range = range(len(current_user.grid_set.all()))
		else: 
			selected_group_users = selected_group.user_set.all()
			i = 0

			for u in selected_group_users: 
				for grid_item in u.grid_set.all(): 
					if (grid_item not in current_user_grid) and (current_user not in grid_item.connectors.all()): 
						current_user_grid.append(grid_item)
						grid_list_range.append(i)
						i += 1


	# Group update form

	# all_groups = []
	# for group in current_user.groups: 
	# 	all_groups.append(group)

	'''
	Puts all current_user's groups into a list.
	'''

	all_groups = current_user.groups.all()

	'''
	If user selected to view one of his groups, then get that group and show it 
	(through the variable show_this_group). Otherwise, if the user didn't select
	a group, then default view the user's own default group: My own connections 
	for... If that doesn't exist, create it. 
	'''

	if group_pk != None: # if user clicked on existing group, switch to that group's view
		show_this_group = current_user.groups.get(id=group_pk)
	else: # on initial load, load default group
		try: # see if that group exists 
			show_this_group = current_user.groups.get(name=default_group_name)
		except(KeyError, Group.DoesNotExist): # if not, create it 
			try:
				show_this_group = current_user.groups.add(Group.objects.get(name=default_group_name))
			except(KeyError, Group.DoesNotExist):
				# default_group_name = 'My own connections for: %s' % email
				show_this_group = current_user.groups.create(name=default_group_name)
				current_user.save()


	request.session['current_user_grid'] = current_user_grid
	request.session['grid_list_range'] = grid_list_range
	request.session['show_this_group'] = show_this_group
	request.session['all_groups'] = all_groups
	request.session['group_pk'] = group_pk
	# request.session['sort_filter'] = sort_filter

	# return HttpResponseRedirect(reverse(sort_filter, kwargs={
	# 	'current_user_grid' : current_user_grid, 
	# 	'grid_list_range' : grid_list_range,
	# 	'show_this_group' : show_this_group,
	# 	'all_groups' : all_groups,
	# 	'group_pk' : group_pk,
	# 	'sort_filter' : sort_filter,
	# 	}))


	view_filter = request.session.get('view_filter', None)	

	return HttpResponseRedirect(view_filter)

	# return HttpResponseRedirect('/introkick/home/')


@login_required
def company(request, sort_filter=None, view_filter='/introkick/company/'): # , current_user_grid, grid_list_range, show_this_group, all_groups, group_pk, sort_filter

	current_user_grid = request.session['current_user_grid']

	current_user_grid = sorted(current_user_grid, key=lambda x: x.node_company)

	# return HttpResponseRedirect(reverse('introkick.views.home', kwargs={
	# 	'current_user_grid' : current_user_grid, 
	# 	'grid_list_range' : grid_list_range,
	# 	'show_this_group' : show_this_group,
	# 	'all_groups' : all_groups,
	# 	'group_pk' : group_pk,
	# 	'sort_filter' : sort_filter,
	# 	}))

	request.session['sort_filter'] = sort_filter
	request.session['view_filter'] = view_filter

	request.session['current_user_grid'] = current_user_grid

	return HttpResponseRedirect('/introkick/home')


@login_required
def industry(request, sort_filter=None, view_filter='/introkick/industry/'): # , current_user_grid, grid_list_range, show_this_group, all_groups, group_pk, sort_filter

	current_user_grid = request.session['current_user_grid']

	current_user_grid = sorted(current_user_grid, key=lambda x: x.node_industry)

	# return HttpResponseRedirect(reverse('introkick.views.home', kwargs={
	# 	'current_user_grid' : current_user_grid, 
	# 	'grid_list_range' : grid_list_range,
	# 	'show_this_group' : show_this_group,
	# 	'all_groups' : all_groups,
	# 	'group_pk' : group_pk,
	# 	'sort_filter' : sort_filter,
	# 	}))

	request.session['sort_filter'] = sort_filter
	request.session['view_filter'] = view_filter

	request.session['current_user_grid'] = current_user_grid

	return HttpResponseRedirect('/introkick/home')


@login_required
def email(request):

	# E-mail update form

	error_message_email = ''

	if 'email' in request.POST: # if user entered invalid email, then render error
		if (request.POST['email'] == '') or (request.POST['email'] == 'Enter your email (no spam, ever)'):
			
			error_message_email = 'You didn\'t enter an email.'
			email = "Enter your email (no spam, ever)"

			request.session['error_message_email'] = error_message_email
			request.session['email'] = email

		else: # if user's email was valid, then save and refresh with new email
			user = request.user
			user.email = request.POST['email']
			user.save()

	try: 
		del request.session['route']
		return HttpResponseRedirect('/introkick/home/group/add/')
	except KeyError: 
		return HttpResponseRedirect('/introkick/home')



@login_required
def add(request):

	'''
	This gives user option to request access to an existing group, or creates a new 
	group if it doesn't yet exist. 
	'''

	# Initialize variables for the render_to_response context 

	current_user = request.user
	first_name = current_user.first_name
	last_name = current_user.last_name
	error_message_email = request.session.get('error_message_email', '')
	email = request.session.get('email', current_user.email)
	show_this_group = request.session['show_this_group']
	all_groups = request.session['all_groups']
	group_members = show_this_group.user_set.all()


	request.session['route'] = 'add_group'

	'''
	Captures what the user typed, and splits logic according to whether group 
	already exists.
	'''

	if ('group' in request.POST) and (request.POST['group'] != ''): # if user typed in group name, try to find it, else create
		try: 
			show_this_group = Group.objects.get(name=request.POST['group'])
			group_members = show_this_group.user_set.all()
		except(KeyError, Group.DoesNotExist):
			show_this_group = current_user.groups.create(name=request.POST['group'])
			group_members = show_this_group.user_set.all()
			current_user.save()

		group_member_list = []

		for member, index in zip(group_members, range(len(group_members))): 
			group_member_list.append({}) # iterates and creates a list of dictionary objects
			group_member_list[index]['first_name'] = member.first_name
			group_member_list[index]['last_name'] = member.last_name
			group_member_list[index]['picture_url'] = member.userprofile.user_picture_url
			group_member_list[index]['public_url'] = member.userprofile.user_url


		request.session['show_this_group'] = show_this_group




	return render_to_response('introkick/group.html', 
		{'current_user' : "Introkick network for %s %s" % (first_name, last_name), 
		'first_name' : first_name,
		'last_name' : last_name,
		'error_message_email' : error_message_email,
		'email' : email,
		'db_email' : current_user.email,
		'current_group' : show_this_group,
		'all_groups' : all_groups.all(),
		'group_member_list' : group_member_list,
		'group_member_list_range' : range(len(group_member_list)),
		}, 
		context_instance=RequestContext(request))


	# if ('group' in request.POST) and (request.POST['group'] != ''): # if user typed in group name, try to find it, else create
	# 	try: 
	# 		show_this_group = current_user.groups.add(Group.objects.get(name=request.POST['group']))
	# 		current_user.save()
	# 	except(KeyError, Group.DoesNotExist):
	# 		show_this_group = current_user.groups.create(name=request.POST['group'])
	# 		current_user.save()

	# request.session['show_this_group'] = show_this_group
	
	# return HttpResponseRedirect('/introkick/home')

@login_required
def request_access(request, requester=None, requestee=None):

	# send_mail('Subject here', 'Here is the message.', 'from@example.com', ['to@example.com'], fail_silently=False)


	'''
	- need to flag the requester as having requested a specific group
	- need to capture name, email, username, group name, group_pk
	- how do I capture the target recipient's email to populate in the "to" field 
	'''
	show_this_group = request.session['show_this_group']

	requester_name = '%s %s' % (User.objects.get(username=requester).first_name, User.objects.get(username=requester).last_name)
	requester_email = User.objects.get(username=requester).email
	requester_username = User.objects.get(username=requester).username
	requested_group_name = Group.objects.get(name=show_this_group)
	requested_group_pk = requested_group_name.id



	message = EmailMessage('Approve access for %s - %s' % (requester_name, requester_email), 'Click this link ____ to approve access for %s (%s, %s) to the group %s at primary key %s.' % (requester_name, requester_username, requester_email, requested_group_name, requested_group_pk), 'archimedes@careerhoot.com', [], ['andrewlchen@gmail.com'])

	message.send()

	return HttpResponseRedirect('/introkick/home')


@login_required
def remove(request, group_pk=None):

	'''
	Remove user from a group when user clicks to leave group. 
	'''

	current_user = request.user

	current_user.groups.remove(Group.objects.get(id=group_pk))


	try: 
		del request.session['route']
		return HttpResponseRedirect('/introkick/home/group/add/')
	except KeyError: 
		return HttpResponseRedirect('/introkick/home')


@login_required
def home(request): # , current_user_grid, grid_list_range, show_this_group, all_groups, sort_filter, group_pk=None


	# 1. Populate user's ID variables by parsing user's attributes from LinkedIn API
	current_user = request.user
	first_name = current_user.first_name
	last_name = current_user.last_name
	email = request.session.get('email', current_user.email)
	error_message_email = request.session.get('error_message_email', '')


	grid = []
	

	current_user_grid = request.session['current_user_grid']
	grid_list_range = request.session['grid_list_range']
	show_this_group = request.session['show_this_group']
	all_groups = request.session['all_groups']
	group_pk = request.session['group_pk']
	sort_filter = request.session['sort_filter']





	'''
	This bit of code fetches the current user's grid and grid size on initial load. 
	If user selects a specific group, then it takes all the "connectors" from that
	group and creates a new master grid which is the sum of individual grids of those 
	"connectors." It also builds the size of this new master grid by adding one unit 
	to grid_list_range for each iteration through the loop.
	
	BUG FIX: grid should not show duplicate entries - which is happening bc we are doing a simple append when constructing "current_user_grid"
	BUG FIX: "connected thru" column should not display everyone: only actual 1st deg connections, and not yourself

	'''


	# sorted(current_user_grid, key=itemgetter('node_company'))

	# for current user's grid, read data from DB and generate lists of data 
	
	for g, gindex in zip(current_user_grid, grid_list_range):
		grid.append({}) # iterates and creates a list of dictionary objects
		grid[gindex]['first_name'] = g.node_first_name
		grid[gindex]['last_name'] = g.node_last_name
		grid[gindex]['location'] = g.node_location
		grid[gindex]['industry'] = g.node_industry
		grid[gindex]['picture_url'] = g.node_picture_url
		grid[gindex]['public_url'] = g.node_public_url
		grid[gindex]['title'] = g.node_title
		grid[gindex]['company'] = g.node_company
		grid[gindex]['connectors'] = []
		grid[gindex]['connector_urls'] = []

		for c in range(len(g.connectors.all())):
			grid[gindex]['connectors'].append("%s %s" % (g.connectors.all()[c].first_name, g.connectors.all()[c].last_name))
			grid[gindex]['connector_urls'].append(g.connectors.all()[c].userprofile.user_url)



	return render_to_response('introkick/home.html', 
		{'current_user' : "Introkick network for %s %s" % (first_name, last_name), 
		'first_name' : first_name,
		'last_name' : last_name,
		'error_message_email' : error_message_email,
		'email' : email,
		'db_email' : current_user.email,
		'current_group' : show_this_group,
		'all_groups' : all_groups.all(),
		'grid_list_range' : grid_list_range,
		'grid' : grid,
		'sort_filter' : sort_filter,
		}, 
		context_instance=RequestContext(request))


