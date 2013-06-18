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
    url(r'^oauth_login/oauth_authenticated/?$', 'oauth_authenticated'),
    url(r'^sync/$', 'sync'),
    url(r'^home/$', 'home'),
    url(r'^home/group/$', 'group'),
    url(r'^home/group/(?P<group_pk>\d+)/$', 'group', name='group_pk'),
    url(r'^company/$', 'group', {'x' : 'x.node_company'}),
    url(r'^industry/$', 'group', {'x' : 'x.node_industry'}),
    url(r'^logout/$', 'oauth_logout', name='logout'),
    # url(r'^email/$', 'email'),
)