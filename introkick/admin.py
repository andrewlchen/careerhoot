from django.contrib import admin
from django.contrib.auth.models import Group, AbstractUser
from introkick.models import Grid, UserProfile, InviteMid, Company

# class GroupAdmin(admin.ModelAdmin):
# 	list_display = ('id', 'name', 'permissions')

class InviteMidAdmin(admin.ModelAdmin):
	list_display = ('mid', 'invite_count')
	search_fields = ('mid',)

class GridAdmin(admin.ModelAdmin):
	list_display = ('node_first_name', 'node_last_name', 'node_location', 'node_industry', 'node_mid')
	search_fields = ('node_first_name', 'node_last_name', 'node_location', 'node_industry', 'node_mid')

class CompanyAdmin(admin.ModelAdmin):
	list_display = ('id', 'node_company', 'node_title')
	search_fields = ('node_company', 'node_title')


# class PositionAdmin(admin.ModelAdmin):
# 	list_display = ('node_title', 'node_company', 'node_mid')
# 	search_fields = ('node_title', 'node_company')

class UserProfileAdmin(admin.ModelAdmin):
	list_display = ('user', 'login_count', 'paid', 'subs_expiry')
	list_filter = ('paid', )


# class InviteMidAdmin(admin.ModelAdmin):
# 	list_display = ('mid',)
# 	search_fields = ('mid',)


# admin.site.register(Group, GroupAdmin)
admin.site.register(InviteMid, InviteMidAdmin)
admin.site.register(Grid, GridAdmin)
admin.site.register(Company, CompanyAdmin)
# admin.site.register(Position, PositionAdmin)
admin.site.register(UserProfile, UserProfileAdmin)
# admin.site.register(InviteMid, InviteMidAdmin)