from django.shortcuts import render

# Create your views here.
from rest_framework.decorators import api_view
from rest_framework.response import Response
from . import encoder,decoder
from phe import paillier
from rest_framework import status
import base64

@api_view(['GET'])
def hello_api(request):
    return Response({"message": "Hello API"})

@api_view(['POST'])
def encrypt_images_api(request):
    image_files = request.FILES.getlist("images")
    
    if not image_files:
        return Response({"error": "No image files provided under key 'images'."}, status=status.HTTP_400_BAD_REQUEST)

    response_payload = []
    
    # Generate one keypair for all images (or generate one per image if needed)
    public_key, private_key = paillier.generate_paillier_keypair()

    for image in image_files:
        # Use a function that accepts a file-like object:
        encrypted_chunks = encoder.encode_and_encrypt_image(image, public_key, max_chunks=256)
        
        serialized_chunks = []
        for chunk in encrypted_chunks:
            serialized_chunks.append({
                "ciphertext": str(chunk.ciphertext()),  # Call the method/property to get its value.
                "exponent": chunk.exponent
            })
        
        response_payload.append({
            "filename": image.name,
            "encrypted_chunks": serialized_chunks
        })

    return Response({
        "public_key": {"n": str(public_key.n)},
        "private_key": {"p": str(private_key.p), "q": str(private_key.q)},
        "data": response_payload
    }, status=status.HTTP_200_OK)


@api_view(['POST'])
def decrypt_images_api(request):
    """
    Expects JSON in the following format:
    {
      "public_key": {"n": "..." },
      "private_key": {"p": "...", "q": "..." },
      "data": [
         {
           "filename": "example.jpg",
           "encrypted_chunks": [
               {"ciphertext": "123456789", "exponent": 0},
               ...
           ]
         },
         ...
      ]
    }
    The endpoint returns a JSON response with each filename and its decrypted image as a Base64 string.
    """
    # Check for required keys
    # required_keys = ["public_key", "private_key", "data"]
    required_keys = ["public_key", "private_key", "data"]
    for key in required_keys:
        if key not in request.data:
            return Response({"error": f"Missing required key: '{key}'."},
                            status=status.HTTP_400_BAD_REQUEST)
    
    try:
        public_key_json = request.data["public_key"]
        private_key_json = request.data["private_key"]
        public_key = paillier.PaillierPublicKey(n=int(public_key_json["n"]))
        # Reconstruct private key from its components.
        private_key = paillier.PaillierPrivateKey(public_key, p=int(private_key_json["p"]), q=int(private_key_json["q"]))
    except Exception as e:
        return Response({"error": f"Error reconstructing keys: {str(e)}"},
                        status=status.HTTP_400_BAD_REQUEST)
    
    response_payload = []
    for item in request.data["data"]:
        filename = item.get("filename", "unknown")
        encrypted_chunks = item.get("encrypted_chunks", [])
        try:
            # Use our new helper to decrypt and decode the image data.
            image_bytes = decoder.decrypt_and_decode_image_data(encrypted_chunks, private_key)
            # Convert image bytes into a Base64 string so we can return it in JSON.
            image_b64 = base64.b64encode(image_bytes).decode('utf-8')
        except Exception as e:
            return Response({"error": f"Error decrypting '{filename}': {str(e)}"},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        response_payload.append({
            "filename": filename,
            "image_b64": image_b64
        })
    
    return Response({"data": response_payload}, status=status.HTTP_200_OK)