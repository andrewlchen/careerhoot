import datetime
from django.utils import timezone
from dateutil.relativedelta import relativedelta

from django.db import models
from django.contrib.auth.models import User, Group
from paypal.standard.ipn.signals import *


# Create your models here.

# class Group(models.Model):
# 	group_name = models.CharField(max_length=70, unique=True)

# 	def __unicode__(self):
# 		return self.group_name

class InviteMid(models.Model):
	mid = models.CharField(max_length=20, unique=True)
	invite_count = models.IntegerField(default=0)

# 	def __unicode__(self):
# 		return self.mid

class Grid(models.Model):
	connectors = models.ManyToManyField(User)
	node_mid = models.CharField(max_length=20, unique=True)
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
		ordering = ['node_last_name', 'node_first_name']

class Company(models.Model):
	grid = models.ManyToManyField(Grid)
	node_company = models.CharField(max_length=150, verbose_name='company')
	node_title = models.CharField(max_length=100, verbose_name='title')

	def __unicode__(self):
		return self.node_company

	class Meta:
		ordering = ['node_company']

# class Title(models.Model):
# 	grid = models.ManyToManyField(Grid)
# 	node_title = models.CharField(max_length=100, verbose_name='title')

# 	def __unicode__(self):
# 		return self.node_title


class UserProfile(models.Model):
	# groups = models.ManyToManyField(Group)
	user = models.OneToOneField(User)
	oauth_token = models.CharField(max_length=100)
	oauth_secret = models.CharField(max_length=100)
	login_count = models.IntegerField(default=0)
	# date_joined = models.DateTimeField('date joined')
	paid = models.BooleanField(default=False)
	subs_expiry = models.DateTimeField()
	user_url = models.CharField(max_length=255)
	user_picture_url = models.CharField(max_length=255)
	# random_hash = models.CharField(max_length=6)

	def __unicode__(self):
		return self.user.username

	class Meta:
		ordering = ['user__last_name']


# class InviteMid(models.Model):
# 	mid = models.CharField(max_length=20, unique=True)

# 	def __unicode__(self):
# 		return self.mid


def cancel_sub(sender, **kwargs):
    ipn_obj = sender
    affected_user = UserProfile.objects.get(user=User.objects.get(username=ipn_obj.custom))
    if affected_user.paid == True: 
    	affected_user.paid = False
    affected_user.subs_expiry = timezone.now()
    affected_user.save()
subscription_cancel.connect(cancel_sub)


def recur_sub(sender, **kwargs):
    ipn_obj = sender
    affected_user = UserProfile.objects.get(user=User.objects.get(username=ipn_obj.custom))
    if affected_user.subs_expiry >= timezone.now() + relativedelta(days=27):
    	pass
    else: 
    	affected_user.subs_expiry += relativedelta(months=1)
    if affected_user.paid == False: 
    	affected_user.paid = True
    affected_user.save()
payment_was_successful.connect(recur_sub) 