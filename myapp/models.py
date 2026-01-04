from django.db import models
import os
# Create your models here.
class userreg(models.Model):
    name = models.CharField(max_length=100)
    email = models.CharField(max_length=50)
    password = models.CharField(max_length=100)
    contact = models.CharField(max_length=100)
    address = models.CharField(max_length=200)
    status = models.CharField(max_length=100, default='Deactivated')

    class Meta:
        db_table = "userreg"

# Create your models here.
class ownerreg(models.Model):
    name = models.CharField(max_length=100)
    email = models.CharField(max_length=50)
    password = models.CharField(max_length=100)
    contact = models.CharField(max_length=100)
    address = models.CharField(max_length=200)
    status = models.CharField(max_length=100, default='Deactivated')

    class Meta:
        db_table = "ownerreg"



class TextECCEncryption(models.Model):
    uploader = models.EmailField()
    filename = models.CharField(max_length=100)
    file_path = models.FileField(upload_to=os.path.join('static', 'EnTextFiles'))
    encrypted_data = models.BinaryField()  # Store the encrypted text as binary
    public_key = models.BinaryField()     # Store the public key (to be used for encryption)
    private_key = models.BinaryField()    # Store private key (Optional, use only if needed for decryption)
    status = models.CharField(max_length=100,default='Pending')

    
    def __str__(self):
        return f"Encrypted Message {self.id}"
    
    class Meta:
        db_table = 'TextECCEncryption'



class userrequest(models.Model):
    receiveremail = models.CharField(max_length=100)
    ownername = models.CharField(max_length=100)
    filekey = models.CharField(max_length=100)
    owneremail = models.CharField(max_length=100)
    filename = models.CharField(max_length=100)
    filedata = models.BinaryField()
    status = models.CharField(max_length=100)

    class Meta:
        db_table = "userrequest"


class RequestFiles(models.Model):
    file_id = models.ForeignKey(TextECCEncryption,on_delete=models.CASCADE)
    requester = models.EmailField()
    otp = models.IntegerField(null=True)
    status = models.CharField(max_length=100, default='Pending')

    def __str__(self):
        return f"Request {self.id}"
    
    class Meta:
        db_table = 'RequestFiles'