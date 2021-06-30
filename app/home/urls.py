from django.conf.urls import url 
from home import views
app_name = 'home'
urlpatterns = [ 
    
    url('', views.home_login , name="login"),
    url('logout', views.home_logout ,name="logout"),
]
