from django.urls import path
from .views import hello_api,encrypt_images_api,decrypt_images_api

urlpatterns = [
    path('hello/', hello_api),  
    path('encrypt/', encrypt_images_api, name='encrypt_image_api'),
    path('decrypt/', decrypt_images_api, name='decrypt_images_api'),
]
