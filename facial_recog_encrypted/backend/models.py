from django.db import models

# Create your models here.

class Image(models.Model):
    filename = models.CharField(max_length=255)
    public_key_n = models.TextField()  # Using TextField to store very large numbers
    private_key_p = models.TextField(blank=True, null=True)  # Optional; consider security!
    private_key_q = models.TextField(blank=True, null=True)  # Optional; consider security!
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.filename


class EncryptedChunk(models.Model):
    image = models.ForeignKey(Image, on_delete=models.CASCADE, related_name='chunks')
    chunk_index = models.PositiveIntegerField()  # To preserve order of chunks
    ciphertext = models.TextField()  # Encrypted data as a string
    exponent = models.IntegerField()

    class Meta:
        ordering = ['chunk_index']

    def __str__(self):
        return f"Chunk {self.chunk_index} of {self.image.filename}"