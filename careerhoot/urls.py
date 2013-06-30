# from django.conf.urls.defaults import *

from django.conf.urls import patterns, include, url
from django.contrib import admin
from django.conf import settings

# from django.contrib.auth import views

# from introkick.views import twitter_login, twitter_logout, twitter_authenticated

admin.autodiscover()


# Uncomment the next two lines to enable the admin:
# from django.contrib import admin
# admin.autodiscover()

urlpatterns = patterns('',
    # Examples:
    # url(r'^$', 'careerhoot.views.home', name='home'),
    # url(r'^careerhoot/', include('careerhoot.foo.urls')),

    # Uncomment the admin/doc line below to enable admin documentation:
    # url(r'^admin/doc/', include('django.contrib.admindocs.urls')),

    # Uncomment the next line to enable the admin:
    # url(r'^admin/', include(admin.site.urls)),

	url(r'^', include('introkick.urls')),
    url(r'^admin/', include(admin.site.urls)),
	# url(r'^introkick/logout/$', views.logout, {'next_page': '/introkick'}, name='logout'),
)


urlpatterns += patterns('',
    (r'^static/(?P<path>.*)$', 'django.views.static.serve', {'document_root': '/home/ubuntu/careerhoot/introkick/static/'}),
)