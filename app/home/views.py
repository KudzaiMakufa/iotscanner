from django.shortcuts import render , redirect
from django.http import HttpResponse
from django.contrib import messages
from django.contrib.auth import authenticate , login , logout
from django.contrib.auth.decorators import login_required , permission_required


# Create your views here.

def home_logout(request):
    logout(request)
    return redirect('/home')

def home_login(request):
    if request.method == "POST":

      user = authenticate(username=request.POST.get('username'),password = request.POST.get('password'))
      
      if(user is not None ):
         login(request , user)
         return redirect('/scanner/scan')
      else:
    #    print(request.POST.get('password'))
         messages.add_message(request, messages.ERROR, 'invalid email or password')

    return render(request , "home/signin.html" , {}) 
