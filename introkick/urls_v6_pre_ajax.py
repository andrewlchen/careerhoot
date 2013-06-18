# from django.conf.urls.defaults import *

from django.conf.urls import patterns, include, url
from django.contrib import admin
from introkick.views import *

admin.autodiscover()


# Uncomment the next two lines to enable the admin:
# from django.contrib import admin
# admin.autodiscover()

urlpatterns = patterns('introkick.views',
    # Examples:
    # url(r'^$', 'careerhoot.views.home', name='home'),
    # url(r'^careerhoot/', include('careerhoot.foo.urls')),

    # Uncomment the admin/doc line below to enable admin documentation:
    url(r'^admin/doc/', include('django.contrib.admindocs.urls')),

    # Uncomment the next line to enable the admin:
    url(r'^admin/', include(admin.site.urls)),

    url(r'^$', 'index'), #if logged in, redirect to company; if logged out, redirect to login
    url(r'^login/?$', 'oauth_login'),
    # url(r'^oauth_logout/?$', 'oauth_logout'),
    url(r'^oauth_login/authenticate_user/?$', 'authenticate_user'),
    url(r'^sync/$', 'sync'),
    url(r'^home/$', 'home', name='home'),
    url(r'^home/email/$', 'email', name='email'),
    url(r'^home/group/$', 'group', name='group'),
    url(r'^home/group/(?P<group_pk>\d+)/$', 'group', name='group_pk'),
    url(r'^home/group/add/$', 'add', name='add'),
    url(r'^home/group/remove/(?P<group_pk>\d+)/$', 'remove', name='remove'),    
    url(r'^home/group/request/(?P<requester>[^/]+)/$', 'request_access', name='request_access'),
    url(r'^grant/(?P<group_pk>\d+)/(?P<requester>[^/]+)/$', 'grant_access', name='grant_access'),
    url(r'^groupinvite/$', 'invite_to_group', name='invite_to_group'), 
    url(r'^invite/$', 'invite', name='invite'), 
    url(r'^(?P<sort_filter>company)/$', 'company', {'view_filter' : '/introkick/company/'}), # 
    url(r'^(?P<sort_filter>industry)/$', 'industry', {'view_filter' : '/introkick/industry/'}), # 
    url(r'^logout/$', 'oauth_logout', name='logout'),
    # url(r'^email/$', 'email'),
)