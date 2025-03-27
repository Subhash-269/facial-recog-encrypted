from django.contrib import admin

# Register your models here.
from .models import Image, EncryptedChunk

class EncryptedChunkInline(admin.TabularInline):
    model = EncryptedChunk
    extra = 0

@admin.register(Image)
class ImageAdmin(admin.ModelAdmin):
    list_display = ('filename', 'created_at')
    inlines = [EncryptedChunkInline]

@admin.register(EncryptedChunk)
class EncryptedChunkAdmin(admin.ModelAdmin):
    list_display = ('image', 'chunk_index')