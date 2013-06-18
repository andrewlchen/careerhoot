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

# Import Django modules 
from django.shortcuts import render_to_response, get_object_or_404
from django.http import HttpResponseRedirect, HttpResponse
from django.conf import settings
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User, Group, AnonymousUser
from django.contrib.auth.decorators import login_required
from django.template import RequestContext
from django.core.urlresolvers import reverse

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

	resp, user_temp = client.request("http://api.linkedin.com/v1/people/~:(id,picture-url,public-profile-url,first-name,last-name,email-address,location:(name),industry,positions:(title,company:(name),is-current))", 
		"GET", headers=headers)

	user_dict_temp = json.loads(user_temp)

	# Step 3. Create user attributes.
	first_name = user_dict_temp["firstName"]
	last_name = user_dict_temp["lastName"]
	email = user_dict_temp["emailAddress"]
	user_id = user_dict_temp["id"]
	# user_location = user_dict_temp['location']['name']
	# user_industry = user_dict_temp['industry']
	try:
		user_picture_url = user_dict_temp['pictureUrl']
	except KeyError: 
		user_picture_url = 'No picture given'

	try:
		user_url = user_dict_temp['publicProfileUrl']
	except KeyError: 
		user_url = '#'


	# user_company = []
	# user_title = []

	# i = 0
	# if user_dict_temp['positions']['_total'] > 0:
	# 	while i < len(user_dict_temp['positions']['values']):
	# 		if user_dict_temp['positions']['values'][i]['isCurrent'] == True:

	# 			try: 
	# 				user_company[i]
	# 			except IndexError:
	# 				try:
	# 					user_company.append([user_dict_temp['positions']['values'][i]['company']['name']])
	# 				except KeyError: 
	# 					user_company.append(['No company specified'])
	# 			else: 
	# 				try:
	# 					user_company.append(user_dict_temp['positions']['values'][i]['company']['name'])
	# 				except KeyError: 
	# 					user_company.append('No company specified')

	# 			try: 
	# 				user_title[i]
	# 			except IndexError:
	# 				try: 
	# 					user_title.append([user_dict_temp['positions']['values'][i]['title']])
	# 				except KeyError: 
	# 					user_title.append(['No title specified'])
	# 			else: 
	# 				try: 
	# 					user_title.append(user_dict_temp['positions']['values'][i]['title'])
	# 				except KeyError: 
	# 					user_title.append('No title specified')

	# 		i += 1

	# else: 
	# 	user_company.append('No company specified')
	# 	user_title.append('No title specified')


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
		userprofile.save()

	# Now, authenticate the user and log them in using Django's 
	# pre-built functions for these things. 
	user = authenticate(username=user_id, 
		password=access_token['oauth_token_secret'])
	if user: 
		login(request, user)
		return HttpResponseRedirect('/introkick/sync/')
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
			'error_message' : "Um, login failed."
			})


# @login_required
# def email(request):
	# try:
	# 	user_email = user.email_set.get(pk=request.POST['email'])
	# except(KeyError, Choice.DoesNotExist):
	# 	return render_to_response('introkick/email.html', 
	# 		{'error_message' : 'You didn\'t enter a valid email.', },
	# 		context_instance=RequestContext(request))
	# else:
	# 	user.email = email
	# 	user.save()
	# 	return email

    # if 'email' in request.POST:
    # 	if (request.POST['email'] == '') or (request.POST['email'] == 'Enter your email (no spam, ever)'):
    # 		error_message = 'You didn\'t enter an email.'
    # 		return render_to_response('introkick/company.html', 
    # 			{'error_message' : error_message, 
    # 			'email' : "Enter your email (no spam, ever)"}, 
    # 			context_instance=RequestContext(request))
    # 	else:
    # 		user = request.user.get_profile().user
    # 		user.email = request.POST['email']
    # 		user.save()
    # 		return HttpResponseRedirect('/introkick/company/')
    # else: 
    # 	return render_to_response('introkick/company.html', {'email' : request.user.get_profile().user.email},
    # 		context_instance=RequestContext(request))


# def emailsave(request):

    # if request.POST['email'] == '':
    # 	error_message = 'You didn\'t enter an email.'
    # 	return render_to_response('introkick/email.html', 
    # 		{'error_message' : error_message}, 
    # 		context_instance=RequestContext(request))
    # else:
    # 	user = request.user.get_profile().user
    # 	user.email = request.POST['email']
    # 	user.save()
    #     return HttpResponseRedirect('/introkick/home/')


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
	# grid_titles_range = []

	# 5. Populate helper variables by parsing "super" list from LinkedIn API
	for i in grid_list_range:
		try:
			mids.append(grid_list[i]['id'])
		except KeyError: 
			mids.append('ID unspecified')

		try:
			grid_firstName.append(grid_list[i]['firstName'])
		except KeyError: 
			grid_firstName.append('First name unspecified')

		try:
			grid_lastName.append(grid_list[i]['lastName'])
		except KeyError: 
			grid_lastName.append('Last name unspecified')

		try:
			grid_location.append(grid_list[i]['location']['name'])
		except KeyError: 
			grid_location.append('Location unspecified')

		try:
			grid_industry.append(grid_list[i]['industry'])
		except KeyError: 
			grid_industry.append('Industry unspecified')

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

		try:
			grid_picture_url.append(grid_list[i]['pictureUrl'])
		except KeyError: 
			grid_picture_url.append('No picture given')

		try:
			grid_public_url.append(grid_list[i]['publicProfileUrl'])
		except KeyError: 
			grid_public_url.append('#')



	# 6. Write to DB
	
	for i in grid_list_range:
		try: # see if that mid exists 
			mid = Mid.objects.get(mid=mids[i])
		except(KeyError, Mid.DoesNotExist): # if not, create it 
			mid = Mid.objects.create(mid=mids[i])
		else: # otherwise, use that mid to pull the associated grid 
			try: # try to pull associated grid 
				current_user_grid = Grid.objects.get(node_mid=mid)
			except(KeyError, Grid.DoesNotExist): # if cannot, then create a new grid row and save
				current_user_grid = Grid.objects.create(node_mid=mid)
				current_user_grid.node_first_name = grid_firstName[i]
				current_user_grid.node_last_name = grid_lastName[i]
				current_user_grid.node_location = grid_location[i]
				current_user_grid.node_industry = grid_industry[i]
				current_user_grid.node_picture_url = grid_picture_url[i]
				current_user_grid.node_public_url = grid_public_url[i]
				current_user_grid.connectors.add(request.user)
				current_user_grid.save()
			else: # otherwise, check to make sure existing grid row is still up to date 
				if current_user_grid.node_first_name != grid_firstName[i]:
					current_user_grid.node_first_name = grid_firstName[i]
				if current_user_grid.node_last_name != grid_lastName[i]:
					current_user_grid.node_last_name = grid_lastName[i]
				if current_user_grid.node_location != grid_location[i]:
					current_user_grid.node_location = grid_location[i]
				if current_user_grid.node_industry != grid_industry[i]:
					current_user_grid.node_industry = grid_industry[i]
				if current_user_grid.node_picture_url != grid_picture_url[i]:
					current_user_grid.node_picture_url = grid_picture_url[i]
				if current_user_grid.node_public_url != grid_public_url[i]:
					current_user_grid.node_public_url = grid_public_url[i]
				current_user_grid.save()

				try: # once grid row is up to date, make sure connectors column is up to date too
					current_user_grid.connectors.get(username=request.user.username)
				except(KeyError, User.DoesNotExist):
					current_user_grid.connectors.add(request.user)
					current_user_grid.save()


		# cases
		# 1. user has no positions, then has 1
		# 2. user has no positions, then has 2
		# 3. user changes position, but has same number
		# 4. user has 2 positions, then reduces to 1
		# 5. user has 1 position, then reduces to 0


		# positions_iterator = max(len(grid_titles[i]), len(grid_companies[i]))
		k = 0
		current_user_grid_positions = []

		# for each title and company in the list, make sure Positions table has it

		for title, company in zip(range(len(grid_titles[i])), range(len(grid_companies[i]))):

			# while k < positions_iterator:

			try: # check to see if current mid has positions associated with it 
				current_user_grid_positions = Position.objects.filter(node_mid=Mid.objects.get(mid=mids[i]))

			except(KeyError, Position.DoesNotExist): # if not, create first positions row entry, with title and company, then increment k by 1
				current_user_grid_positions = Position.objects.create(node_mid=Mid.objects.get(mid=mids[i]))
				# current_user_grid_positions[k].node_company = grid_titles[i][j]
				current_user_grid_positions.node_title = grid_titles[i][title]
				current_user_grid_positions.node_company = grid_companies[i][company]
				current_user_grid_positions.save()
				k += 1

			else: 
				try: # otherwise, check to see if the current (k) row exists
					current_user_grid_positions[k]
				except IndexError: # if not, then create that row with appropriate title and company
					mid.position_set.add(Position(node_title=grid_titles[i][title], node_company=grid_companies[i][company]))
				else: # otherwise, check to make sure title and company are up to date; if not, update and then save 
					if current_user_grid_positions[k].node_title != grid_titles[i][title]: 
						current_user_grid_positions[k].node_title = grid_titles[i][title]
					if current_user_grid_positions[k].node_company != grid_companies[i][company]:
						current_user_grid_positions[k].node_company = grid_companies[i][company]				
					current_user_grid_positions[k].save()
				
				k += 1


		# remaining_pos = Position.objects.filter(node_mid=Mid.objects.get(mid=mids[i]))
		# remaining = len(Position.objects.filter(node_mid=Mid.objects.get(mid=mids[i]))) - k

		# for item in range(remaining):
		# 	remaining_pos.pop()
		# 	remaining_pos.pop()


	# 7. Redirect to rendered page
	return HttpResponseRedirect('/introkick/company/')

@login_required
def company(request, group_pk = None):

	# 1. Populate user's ID variables by parsing user's attributes from LinkedIn API
	current_user = request.user
	first_name = current_user.first_name
	last_name = current_user.last_name
	email = current_user.email
	default_group_name = 'My own connections for: %s' % email


	'''
	Below will require changing the grid calls once groups are 
	introduced. Right now, the grid being displayed is limited to the 
	currently signed in user. 
	'''

	# 2. Initialize other variables
	# grid_firstName = []
	# grid_lastName = []
	# grid_location = []
	# grid_industry = []
	# grid_picture_url = []
	# grid_public_url = []
	# grid_titles = []
	# grid_companies = []
	# grid_connectors = []
	# grid_connector_urls = []

	grid = []
	grid_list_range = []

	# Need to build this list of companies, then match against your grid list before displaying it to end user
	company_list = []

	for company in Position.objects.values('node_company').distinct().order_by('node_company'): 
		company_list.append(company['node_company'])

	'''
	This bit of code fetches the current user's grid and grid size on initial load. 
	If user selects a specific group, then it takes all the "connectors" from that
	group and creates a new master grid which is the sum of individual grids of those 
	"connectors." It also builds the size of this new master grid by adding one unit 
	to grid_list_range for each iteration through the loop.
	
	BUG FIX: grid should not show duplicate entries - which is happening bc we are doing a simple append when constructing "current_user_grid"
	BUG FIX: "connected thru" column should not display everyone: only actual 1st deg connections, and not yourself

	'''

	if group_pk == None: 
		u = User.objects.get(username=request.user.username)
		current_user_grid = u.grid_set.all()
		grid_list_range = range(len(u.grid_set.all()))
	else: 
		selected_group = Group.objects.get(id=group_pk)
		selected_group_users = selected_group.user_set.all()
		current_user_grid = []
		i = 0

		for user in selected_group_users: 
			for grid_item in user.grid_set.all(): 
				current_user_grid.append(grid_item)
				grid_list_range.append(i)
				i += 1


	# for current user's grid, read data from DB and generate lists of data 
	
	# gindex = range(len(Grid.objects.all()))
	for g, gindex in zip(current_user_grid, grid_list_range):
		grid.append({}) # iterates and creates a list of dictionary objects
		grid[gindex]['first_name'] = g.node_first_name
		grid[gindex]['last_name'] = g.node_last_name
		grid[gindex]['location'] = g.node_location
		grid[gindex]['industry'] = g.node_industry
		grid[gindex]['picture_url'] = g.node_picture_url
		grid[gindex]['public_url'] = g.node_public_url
		grid[gindex]['connectors'] = []
		grid[gindex]['connector_urls'] = []
		grid[gindex]['titles'] = []
		grid[gindex]['companies'] = []

		for c in range(len(g.connectors.all())):
			grid[gindex]['connectors'].append("%s %s" % (g.connectors.all()[c].first_name, g.connectors.all()[c].last_name))
			grid[gindex]['connector_urls'].append(g.connectors.all()[c].userprofile.user_url)

		# for each grid person, build list of their titles and companies

		pos = Position.objects.filter(node_mid=Mid.objects.get(mid=g.node_mid))
		rev_counter = len(pos)

		for p in pos:
			grid[gindex]['titles'].append(pos[len(pos) - rev_counter].node_title)
			grid[gindex]['companies'].append(pos[len(pos) - rev_counter].node_company)
			rev_counter -= 1

	# 3. Email update form + group update form

	all_groups = current_user.groups

	if ('group' in request.POST) and (request.POST['group'] != ''): # if user typed in group name, try to find it, else create
		try: 
			show_this_group = current_user.groups.add(Group.objects.get(name=request.POST['group']))
			current_user.save()
		except(KeyError, Group.DoesNotExist):
			show_this_group = current_user.groups.create(name=request.POST['group'])
			current_user.save()
	elif group_pk != None: # if user clicked on existing group, switch to that group's view
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

	error_message_email = ''

	if 'email' in request.POST: # if user entered invalid email, then render error
		if (request.POST['email'] == '') or (request.POST['email'] == 'Enter your email (no spam, ever)'):
			
			error_message_email = 'You didn\'t enter an email.'
			email = "Enter your email (no spam, ever)"

		else: # if user's email was valid, then save and refresh with new email
			user = request.user
			user.email = request.POST['email']
			user.save()
			# return HttpResponseRedirect('/introkick/company/')

			
			# return render_to_response('introkick/company.html', 
			# 	{'user' : "Introkick network for %s %s" % (first_name, last_name), 
			# 	# 'error_message' : error_message,
			# 	'email' : email,
			# 	'current_group' : show_this_group,
			# 	'all_groups' : all_groups.all(),
			# 	'grid_list_range' : grid_list_range,
			# 	'grid' : grid,
			# 	# 'grid_firstName' : grid_firstName,
			# 	# 'grid_lastName' : grid_lastName,
			# 	# 'grid_location' : grid_location,
			# 	# 'grid_industry' : grid_industry,
			# 	# 'grid_titles' : grid_titles,
			# 	# 'grid_companies' : grid_companies,
			# 	# 'grid_positions' : grid_positions,
			# 	# 'grid_picture_url' : grid_picture_url,
			# 	# 'grid_public_url' : grid_public_url,
			# 	'first_name' : first_name,
			# 	'last_name' : last_name,
			# 	# 'grid_connectors' : grid_connectors,
			# 	# 'grid_connector_urls' : grid_connector_urls,
			# 	}, 
			# 	context_instance=RequestContext(request))



	return render_to_response('introkick/company.html', 
		{'user' : "Introkick network for %s %s" % (first_name, last_name), 
		'error_message_email' : error_message_email,
		'email' : email,
		'db_email' : current_user.email,
		'current_group' : show_this_group,
		'all_groups' : all_groups.all(),
		'grid_list_range' : grid_list_range,
		'grid' : grid,
		'company_list' : company_list,
		# 'grid_firstName' : grid_firstName,
		# 'grid_lastName' : grid_lastName,
		# 'grid_location' : grid_location,
		# 'grid_industry' : grid_industry,
		# 'grid_titles' : grid_titles,
		# 'grid_companies' : grid_companies,
		# 'grid_positions' : grid_positions,
		# 'grid_picture_url' : grid_picture_url,
		# 'grid_public_url' : grid_public_url,
		'first_name' : first_name,
		'last_name' : last_name,
		# 'grid_connectors' : grid_connectors,
		# 'grid_connector_urls' : grid_connector_urls,
		}, 
		context_instance=RequestContext(request))


		# return render_to_response('introkick/company.html', 
		# 	{'user' : "Introkick network for %s %s" % (first_name, last_name), 
		# 	'email' : email,
		# 	'current_group' : show_this_group,
		# 	'all_groups' : all_groups.all(),
		# 	'grid_list_range' : grid_list_range,
		# 	'grid' : grid,
		# 	# 'grid_firstName' : grid_firstName,
		# 	# 'grid_lastName' : grid_lastName,
		# 	# 'grid_location' : grid_location,
		# 	# 'grid_industry' : grid_industry,
		# 	# 'grid_titles' : grid_titles,
		# 	# 'grid_companies' : grid_companies,
		# 	# 'grid_positions' : grid_positions,
		# 	# 'grid_picture_url' : grid_picture_url,
		# 	# 'grid_public_url' : grid_public_url,
		# 	'first_name' : first_name,
		# 	'last_name' : last_name,
		# 	# 'grid_connectors' : grid_connectors,
		# 	# 'grid_connector_urls' : grid_connector_urls,
		# 	}, 
		# 	context_instance=RequestContext(request))



def industry(request, username):
	return HttpResponse("This is the post-login industry page.")

def detail(request, user_mid):
	mid = get_object_or_404(UserProfile, pk=user_mid)
	return render_to_response('introkick/detail.html', {'user_mid': mid},
		context_instance=RequestContext(request))
