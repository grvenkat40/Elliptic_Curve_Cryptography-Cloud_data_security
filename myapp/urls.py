from django.urls import path
from . import views
from .views import *

urlpatterns = [
    path('', views.index, name="index"),
    path('login', views.login, name='login'),
    path('signup', views.signup, name='signup'),
    path('about', views.about, name = "about"),
    path('contact', views.contact, name='contact'),
    path('cloudhome', views.cloudhome, name='cloudhome'),
    path('viewusers/', views.viewusers, name='viewusers'),
    path('acceptuser/<int:id>', views.acceptuser, name='acceptuser'),
    path('viewowners/', views.viewowners, name='viewowners'),
    path('acceptowner/<int:id>', views.acceptowner, name='acceptowner'),
    path('ownerhome', views.ownerhome, name='ownerhome'),
    path('userhome', views.userhome, name='userhome'),
    path('uploadfiles', views.uploadfiles, name='uploadfiles'),
    path('viewourfile', views.viewourfile, name='viewourfile'),
    path('viewallfile', views.viewallfile, name='viewallfile'),
    path('sendrequest/<int:id>/', views.sendrequest, name='sendrequest'),
    path('viewresponse', views.viewresponse, name='viewresponse'),
    path('viewrequests', views.viewrequests, name='viewrequests'),
    path('accept/<int:id>', views.accept, name='accept'),
    path('viewrequestcloud', views.viewrequestcloud, name='viewrequestcloud'),
    path('sendkey/<int:id>/', views.sendkey, name='sendkey'),
     path('decryptfile/<int:id>/', views.decryptfile, name='decryptfile'),
     path('logout/', views.logout, name='logout'),
     path('downloadfile/<int:id>/', views.downloadfile, name='downloadfile'),




    # path('decrypt_files/<int:id>/', views.decrypt_files, name='decrypt_files'),
    # path('decrypt_file', views.decrypt_file, name='decrypt_file'),
    # path('decrypt_file/<int:file_id>/', views.download_file, name='decrypt_file'),
    #  path('decrypt', views.decrypt_file_view, name='decrypt_file'),
    # path('file_download/<int:file_id>/', views.download_file_view, name='download_file_view'),
    # path('decrypt_file/<int:file_id>/', views.download_file, name='decrypt_file'),
]
  

