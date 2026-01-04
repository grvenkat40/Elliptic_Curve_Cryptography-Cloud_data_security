from django.shortcuts import render, redirect
from django.contrib import messages
from . models import *
import os
from django.contrib.auth import authenticate, login as auth_login
import uuid
from .ecc import *
import random
from django.conf import settings
from django.core.mail import send_mail
import base64


# templates
INDEXPAGE = "index.html"
loginpage = "login.html"
Aboutpage = "about.html"
cloudhomepage = 'cloudhome.html'
viewuseracpt = 'viewuseracpt.html'
viewowneracpt = 'viewowneracpt.html'
userhome = 'userhome.html'
ownerhomepage = 'ownerhome.html'
userhomepage = 'userhome.html'
uploaddata = 'upload.html'
viewmyfile = 'viewourfile.html'
viewalfile = "viewallfile.html"
viewresponsefile = 'viewresponse.html'
viewrequestfile = 'viewrequest.html'
viewcloudrequset = "cloudresponse.html"


def index(req):
    return render(req, INDEXPAGE)



def login(request):
    if request.method == "POST":
        login_type = request.POST['login_type']
        email = request.POST['email']
        password = request.POST['password']

        if not login_type or not email or not password:
            messages.error(request, "All fields are required.")
            return render(request, loginpage)

        if login_type == "cloudserver":
            if email == "cloud@gmail.com" and password == "cloud":
                request.session['email'] = email
                request.session['name'] = 'Cloud Server Admin'
                return render(request, cloudhomepage)
            else:
                messages.error(request, 'Invalid cloud server credentials.')
                return render(request, loginpage)

        elif login_type == "user":
            try:
                user = userreg.objects.get(email=email, password=password, status='Activated')
                request.session['email'] = user.email
                request.session['name'] = user.name
                print(user.name)
                return render(request, userhomepage, {'user': user})
            except userreg.DoesNotExist:
                messages.error(request, "Invalid user credentials or account not activated.")
                return render(request, loginpage)

        elif login_type == "owner":
            try:
                owner = ownerreg.objects.get(email=email, password=password, status='Activated')
                request.session['email'] = owner.email
                request.session['name'] = owner.name
                return render(request, ownerhomepage, {'name': owner.name})
            except ownerreg.DoesNotExist:
                messages.error(request, "Invalid owner credentials or account not activated.")
                return render(request, loginpage)
        else:
            messages.error(request, "Invalid login type selected.")
            return render(request, loginpage)

    return render(request, loginpage)


def logout(request):
    del request.session['email']
    del request.session['name']
    return redirect('index')

def about(request):
    return render(request, "about.html")

def contact(request):
    return render(request, "contact.html")

def signup(request):
    if request.method == "POST":
        signup_type = request.POST['signup_type']  # Determine the type of signup
        name = request.POST['name']
        email = request.POST['email']
        password = request.POST['password']
        conpassword = request.POST['password2']
        contact = request.POST['contact']
        address = request.POST['address']
        if password == conpassword:
            if signup_type == "user":
                # Check if the user already exists
                data = userreg.objects.filter(email=email).exists()
                if not data:
                    # Create a new user
                    data_insert = userreg(
                        name=name, email=email, password=password, contact=contact, address=address)
                    data_insert.save()
                    messages.success(request, 'User registered successfully.')
                    return redirect('login')
                else:
                    messages.warning(request, 'User details already exist.')
                    return redirect('signup')
            elif signup_type == "owner":
                # Check if the owner already exists
                data = ownerreg.objects.filter(email=email).exists()  # Assuming ownerreg is the model for owners
                if not data:
                    # Create a new owner
                    data_insert = ownerreg(
                        name=name, email=email, password=password, contact=contact, address=address)
                    data_insert.save()
                    messages.success(request, 'Owner registered successfully.')
                    return redirect('login')
                else:
                    messages.warning(request, 'Owner details already exist.')
                    return redirect('signup')
            else:
                messages.warning(request, 'Invalid signup type.')
                return redirect('signup')
        else:
            messages.error(request, 'Passwords do not match.')
            return redirect('signup')
    return render(request, 'signup.html')  # Render a common signup page

def cloudhome(req):
    return render(req, cloudhomepage)

def viewusers(request):
    usersdata = userreg.objects.filter(status='Deactivated')
    return render(request, viewuseracpt, {'usersdata': usersdata})

# cloud server accept the user request
def acceptuser(request, id):
    data = userreg.objects.get(id=id)
    data.status = 'Activated'
    data.save()
    # Add a success message
    messages.success(request, f'The User "{data.name}" has been successfully activated.')
    return redirect("viewusers")

def viewowners(request):
    ownersdata = ownerreg.objects.filter(status='Deactivated')
    return render(request, viewowneracpt, {'ownersdata': ownersdata})

# cloud server accept the user request
def acceptowner(request, id):
    data = ownerreg.objects.get(id=id)
    data.status = 'Activated'
    data.save()
    # Add a success message
    messages.success(request, f'The owner "{data.name}" has been successfully activated.')
    return redirect("viewowners")

def ownerhome(request):
    email = request.session.get('email')

    if email:
        owner = ownerreg.objects.get(email=email)
        return render(request, ownerhomepage, {'name': owner.name})
    else:
        return redirect('login')


def userhome(request):
    # Ensure that you retrieve the user's email from the session
    email = request.session.get('email')
    
    if email:
        # Get the user object from the database
        user = userreg.objects.get(email=email)
        print(99999999,user)
        
        # Pass the user's name to the template
        return render(request, 'userhome.html', {'name': user.name})
    else:
        # Handle the case where the user is not logged in or email is not in session
        return redirect('login')  # Redirect to login page



from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

# Generate ECC private key
private_key = ec.generate_private_key(ec.SECP256R1())

# Serialize private key to PEM format
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

# Serialize public key to PEM format
public_key = private_key.public_key()
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Encrypt the file data
def encrypt_file(public_key, file_data):
    # Generate a shared key using ECDH (Elliptic Curve Diffie-Hellman)
    shared_key = private_key.exchange(ec.ECDH(), public_key)

    # Derive a symmetric key using PBKDF2HMAC
    salt = os.urandom(16)  # Generate a random salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = kdf.derive(shared_key)

    # Pad the file data to match AES block size (128 bits / 16 bytes)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(file_data) + padder.finalize()

    # Generate random Initialization Vector (IV) for CBC mode
    iv = os.urandom(16)

    # Encrypt the data using AES in CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Concatenate salt, IV, and encrypted data for decryption
    return salt + iv + encrypted_data


import uuid

from django.conf import settings

def uploadfiles(request):
    # TextECCEncryption.objects.all().delete()

    # login = request.session['login']
    email = request.session['email']

    if request.method == 'POST':
        file =  request.FILES['file']
        upload_folder = os.path.join(settings.BASE_DIR, 'static', 'EnTextFiles')

        if not os.path.exists(upload_folder):
            os.makedirs(upload_folder)
        
        unique_filename = f"{uuid.uuid4().hex}_{file.name}"

    
        file_path = os.path.join(upload_folder, unique_filename)
        relative_file_path = os.path.relpath(file_path, settings.BASE_DIR)

        # Save the file to the server (non-encrypted)
        with open(relative_file_path, 'wb') as f:
            for chunk in file.chunks():
                f.write(chunk)

        # Load the public key
        public_key = serialization.load_pem_public_key(public_pem)

        # Read file data and encrypt it
        with open(relative_file_path, 'rb') as f:
            file_data = f.read()

        encrypted_message = encrypt_file(public_key, file_data)

        # Save the encrypted file
        with open(relative_file_path, 'wb') as f:
            f.write(encrypted_message)

        # Store the encrypted file data and metadata
        upload = TextECCEncryption.objects.create(
            filename=unique_filename,
            encrypted_data=encrypted_message,  # Store encrypted file as bytes
            uploader=email,
            file_path=relative_file_path,
            public_key=public_pem,  # Save public key as PEM
            private_key=private_pem
        )
        upload.save()

        messages.success(request, 'File uploaded and encrypted successfully')
        return redirect('uploadfiles')
    return render(request, 'uploadfiles.html')





#view user file 
def viewourfile(request):
    viewfile = TextECCEncryption.objects.filter(uploader=request.session['email'])
    return render(request, 'viewfiles.html', {'data': viewfile})

#view all the uploaded files 
def viewallfile(request):
    data = TextECCEncryption.objects.all()
    return render(request, 'viewallfile.html', {'data': data})

def sendrequest(request,id):
    # login =  request.session['login']
    email =  request.session['email']
    data = TextECCEncryption.objects.get(id=id)
    req = RequestFiles.objects.create(
        file_id = data,
        requester = email
    )
    req.save()
    messages.success(request, 'File Request Sent Successfully!')
    return redirect('viewallfile')


from django.core.paginator import Paginator


def viewrequests(request):
    # RequestFiles.objects.all().delete()
    # TextECCEncryption.objects.all().delete()

    # login =  request.session['login']
    email =  request.session['email']
    requests = RequestFiles.objects.filter(file_id__uploader=email, status="Pending")

    paginator = Paginator(requests, 4)  # 10 items per page_
    page_number = request.GET.get('page')  # Get the current page number from the GET request
    page_obj = paginator.get_page(page_number)  # Get the page object
    return render(request, 'viewrequests.html', {'data': page_obj})



#view user file 
def viewresponse(request):
    viewfile = RequestFiles.objects.filter(status='keysent',requester=request.session['email'])
    return render(request, viewresponsefile, {'data': viewfile})  



# cloud server accept the user request
def accept(request, id):
    data = RequestFiles.objects.get(id=id)
    data.status = 'Processed'
    data.save()

    messages.success(request, 'Request Processed Successfully!')
    return redirect('viewrequests')


def viewrequestcloud(request):
    viewfiles = RequestFiles.objects.filter(status='Processed')
    return render(request, viewcloudrequset, {'data': viewfiles})
  
from django.core.paginator import Paginator

from django.core.mail import send_mail
import random
def sendkey(request, id):
    data = RequestFiles.objects.get(id=id)
    data.status = 'keysent'
    data.otp = random.randint(000000,999999)
    data.save()
    email_subject = 'Decrypt Key Details'
    email_message = f'Hello {data.requester},\n\nWelcome To Our Website!\n\nHere are your Key details:\nEmail: {data.requester}\nKey: {data.otp}\n\nPlease keep this information private.\n\nBest regards,\n CSIT B-12 Team'
    send_mail(email_subject, email_message, 'cse.takeoff@gmail.com', [data.requester])
    messages.success(request, 'Key Sent Successfully!')
    return redirect('viewrequests')




from django.http import HttpResponse
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

def decrypt_file_data(private_key, encrypted_data, public_key):
    # Extract the salt (16 bytes), IV (16 bytes), and encrypted message
    salt = encrypted_data[:16]  # First 16 bytes are the salt
    iv = encrypted_data[16:32]  # Next 16 bytes are the IV
    encrypted_message = encrypted_data[32:]  # The rest is the encrypted message

    # Derive shared key using the private key and corresponding public key (ECDH)
    shared_key = private_key.exchange(ec.ECDH(), public_key)

    # Derive symmetric AES key using PBKDF2HMAC
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,  # Use the same salt as during encryption
        iterations=100000,
    )
    key = kdf.derive(shared_key)

    # Decrypt the file data using AES in CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_message) + decryptor.finalize()

    # Unpad the decrypted data
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()

    return unpadded_data




def decryptfile(request, id):
    # login = request.session['login']
    data = RequestFiles.objects.get(id=id)
    # print(data.file_id.id)
    if request.method == 'POST':
        key = request.POST['key']
        if data.otp == int(key):
            fileid = data.file_id.id
            return downloadfile(request,fileid)
            # messages.success(request, 'File Downloaded Successfully!')
            # return redirect('viewresponses')
        else:
            messages.error(request, 'Invalid Key!')
            return redirect('decryptfile',id)
       
    return render(request, 'download.html',{'id':id,'file_name':data.file_id.filename})

    



def downloadfile(request, id):
    try:
        # Fetch the encrypted record from the database
        encrypted_record = TextECCEncryption.objects.get(id=id)

            # Decrypt the text file
        private_key = serialization.load_pem_private_key(
            encrypted_record.private_key,
            password=None
        )

        public_key_pem = encrypted_record.public_key
        public_key = serialization.load_pem_public_key(public_key_pem)

        encrypted_data = encrypted_record.encrypted_data  # Encrypted data saved in the DB

        # Decrypt the file data
        decrypted_data = decrypt_file_data(private_key, encrypted_data, public_key)

        # Send the decrypted text file as an HTTP response
        response = HttpResponse(decrypted_data, content_type='application/octet-stream')
        response['Content-Disposition'] = f'attachment; filename="{encrypted_record.filename}"'
        return response

       
    except TextECCEncryption.DoesNotExist:
        # Handle file not found in the database
        messages.error(request, "File not found or already deleted.")
        return redirect('viewresponses')

    except Exception as e:
        # Handle general errors during decryption
        messages.error(request, f"An error occurred during decryption: {str(e)}")
        return redirect('viewresponses')











# import base64

# def sendkey(request, id):
#     data = userrequest.objects.filter(id=id)
#     print(data)
    
#     for i in data:
#         # The tuple 'dc' contains only two elements: receiveremail and filekey
#         dc = i.receiveremail, i.filekey
#         print(dc)
    
#     receiveremail = dc[0]  # This gets the receiveremail
#     filekey = dc[1]  # This gets the filekey (in bytes)
    
#     # Convert filekey to a Base64 string for email
#     filekey_str = base64.b64encode(filekey).decode('utf-8')
    
#     print(receiveremail, filekey_str)
    
#     # Debug output
#     print(f"ID: {id}, Receiver Email: {receiveremail}, Status: 'Processed'")
    
#     # Query the user request with the given id, receiveremail, and status 'Processed'
#     user_requests = userrequest.objects.filter(id=id, receiveremail=receiveremail, status='Processed')
    
#     if not user_requests.exists():
#         # If no matching request is found, add an error message and redirect
#         messages.error(request, "No matching request found or the request has already been processed.")
#         return redirect("viewrequestcloud")
    
#     key = filekey_str  # Now it's a Base64 encoded string
#     email = user_requests[0].receiveremail
    
#     subject = "No reply"
#     content = f'The private key to decrypt the file is: {key}'
#     message_body = f"{content}\n\nThis message is automatically generated, so please do not reply.\n\nThank you.\nRegards,\nCloud Service Provider."
    
#     email_from = settings.EMAIL_HOST_USER
#     recipient_list = [email]
    
#     # Send the email
#     send_mail(subject, message_body, email_from, recipient_list, fail_silently=False)
    
#     # Update the status of the request to 'approved'
#     user_request = user_requests.first()
#     user_request.status = 'approved'
#     user_request.save()

#     # Add a success message and redirect
#     messages.success(request, 'Key has been sent successfully.')
#     return redirect("viewrequestcloud")




# from cryptography.hazmat.primitives import padding
# from cryptography.hazmat.primitives.asymmetric import ec
# from cryptography.hazmat.primitives import serialization
# from cryptography.hazmat.primitives import hashes
# from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
# from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
# import os

# # Generate ECC private key
# private_key = ec.generate_private_key(ec.SECP256R1())

# # Serialize private key to PEM format
# private_pem = private_key.private_bytes(
#     encoding=serialization.Encoding.PEM,
#     format=serialization.PrivateFormat.TraditionalOpenSSL,
#     encryption_algorithm=serialization.NoEncryption()
# )

# # Serialize public key to PEM format
# public_key = private_key.public_key()
# public_pem = public_key.public_bytes(
#     encoding=serialization.Encoding.PEM,
#     format=serialization.PublicFormat.SubjectPublicKeyInfo
# )

# # Load private key from PEM
# loaded_private_key = serialization.load_pem_private_key(
#     private_pem,
#     password=None
# )

# # Load public key from PEM
# loaded_public_key = serialization.load_pem_public_key(public_pem)

# # Encrypt data
# def encrypt_message(public_key, message):
#     # Get the public key in a format that can be used for key exchange
#     public_key_bytes = public_key.public_bytes(
#         encoding=serialization.Encoding.PEM,
#         format=serialization.PublicFormat.SubjectPublicKeyInfo
#     )
    
#     # Use ECDH for key exchange
#     shared_key = loaded_private_key.exchange(ec.ECDH(), serialization.load_pem_public_key(public_key_bytes))
    
#     # Derive a key using PBKDF2 or other KDF
#     kdf = PBKDF2HMAC(
#         algorithm=hashes.SHA256(),
#         length=32,
#         salt=b'salt',
#         iterations=100000,
#     )
#     key = kdf.derive(shared_key)
    
#     # Pad the message using PKCS#7
#     padder = padding.PKCS7(128).padder()
#     padded_message = padder.update(message) + padder.finalize()
    
#     # Encrypt the message using AES
#     iv = os.urandom(16)
#     cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
#     encryptor = cipher.encryptor()
#     encrypted_message = encryptor.update(padded_message) + encryptor.finalize()
    
#     return iv + encrypted_message

# # Decrypt data
# def decrypt_message(private_key, encrypted_message):
#     # Get the public key in a format that can be used for key exchange
#     public_key_bytes = loaded_public_key.public_bytes(
#         encoding=serialization.Encoding.PEM,
#         format=serialization.PublicFormat.SubjectPublicKeyInfo
#     )
    
#     # Use ECDH for key exchange
#     shared_key = private_key.exchange(ec.ECDH(), serialization.load_pem_public_key(public_key_bytes))
    
#     # Derive a key using PBKDF2 or other KDF
#     kdf = PBKDF2HMAC(
#         algorithm=hashes.SHA256(),
#         length=32,
#         salt=b'salt',
#         iterations=100000,
#     )
#     key = kdf.derive(shared_key)
    
#     # Decrypt the message using AES
#     iv = encrypted_message[:16]
#     encrypted_message = encrypted_message[16:]
#     cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
#     decryptor = cipher.decryptor()
#     decrypted_padded_message = decryptor.update(encrypted_message) + decryptor.finalize()
    
#     # Unpad the message using PKCS#7
#     unpadder = padding.PKCS7(128).unpadder()
#     unpadded_message = unpadder.update(decrypted_padded_message) + unpadder.finalize()
    
#     return unpadded_message

# # Example usage
# # message = b"Hello shiva "
# # encrypted_message = encrypt_message(loaded_public_key, message)
# # decrypted_message = decrypt_message(loaded_private_key, encrypted_message)
# # print(encrypted_message)
# # print(decrypted_message)

# def decrypt(request, id):
#     fil=userrequest.objects.get(id=id)
#     decrypted_message = decrypt_message(fil.filekey, fil.filedata)
#     print(decrypted_message)