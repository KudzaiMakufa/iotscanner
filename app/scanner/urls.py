from django.urls import path
from scanner import views
app_name = 'scanner'
urlpatterns = [ 
    path('scan', views.scan_network , name="scan"),
    path('history', views.display_history , name="history"),
    path('delete/<int:device_id>', views.device_delete , name="delete"),
    path('livecam/<int:device_id>', views.livecam , name="livecam"),
    path('exploits/<int:device_id>', views.scan_vulnerabilities, name="exploits"),
    
]