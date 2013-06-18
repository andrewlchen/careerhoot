import datetime
from django.utils import timezone

from django.db import models
from django.contrib.auth.models import User

# Create your models here.

class Group(models.Model):
	group_name = models.CharField(max_length=70, unique=True)

	def __unicode__(self):
		return self.group_name

class Mid(models.Model):
	mid = models.CharField(max_length=20, unique=True)

	def __unicode__(self):
		return self.mid

class Grid(models.Model):
	connectors = models.ManyToManyField(User)
	node_mid = models.OneToOneField(Mid)
	node_first_name = models.CharField(max_length=50, verbose_name='first_name')
	node_last_name = models.CharField(max_length=50, verbose_name='last_name')
	node_location = models.CharField(max_length=50, verbose_name='location')
	node_industry = models.CharField(max_length=50, verbose_name='industry')
	node_picture_url = models.CharField(max_length=255)
	node_public_url = models.CharField(max_length=255)

	def __unicode__(self):
		return str(self.node_mid)
		# s = ''
		# for c in self.connectors.all():
		# 	s = s + str(c) + ", "
		# return s

	class Meta:
		ordering = ['node_last_name']

class Position(models.Model):
	node_mid = models.ForeignKey(Mid)
	node_title = models.CharField(max_length=70, verbose_name='title')
	node_company = models.CharField(max_length=70, verbose_name='company')

	def __unicode__(self):
		return self.node_company

	class Meta:
		ordering = ['node_company']

class UserProfile(models.Model):
	groups = models.ManyToManyField(Group)
	user = models.OneToOneField(User)
	oauth_token = models.CharField(max_length=100)
	oauth_secret = models.CharField(max_length=100)
	login_count = models.IntegerField(default=0)
	date_joined = models.DateTimeField('date joined')
	paid = models.BooleanField(default=False)
	user_url = models.CharField(max_length=255)

	def __unicode__(self):
		return self.user.username

	class Meta:
		ordering = ['user__last_name']

