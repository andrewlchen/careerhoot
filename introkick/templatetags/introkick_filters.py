from django import template

register = template.Library()

@register.filter
def lookup(list, index):
    return list[index]

@register.filter(name='zip')
def zip_lists(a, b):
  return zip(a, b)

@register.filter(name='range_len') 
def range_len(list):
	if list: 
		return range(len(list))