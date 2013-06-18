from django import forms

class EmailUpdate(forms.Form):
	email = forms.EmailField(
		required=True, 
		label='Update your e-mail:', 
		error_messages={'required': 'You didn\'t enter a valid email.'},
	)

class GroupUpdate(forms.Form):
	group = forms.CharField(
		required=False, 
		label='Add or join a group:',
		initial='Add or join a group'
	)

# class JoinGroup(forms.Form):
# 	group_member = forms.BooleanField(required=False)


class InviteOthersToGroup(forms.Form):
	email = forms.EmailField(
		required=False, 
		label='Invite others to this group:', 
		initial='name@example.com', 
		error_messages={'required': 'You didn\'t enter a valid email.'},
	)

class InviteOthers(forms.Form):
	email = forms.EmailField(
		required=False, 
		label='Invite others to IntroKick:', 
		initial='name@example.com', 
		error_messages={'required': 'You didn\'t enter a valid email.'},
	)
