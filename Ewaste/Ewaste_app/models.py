from django.db import models
from datetime import timedelta
from django.utils import timezone

# Create your models here.

class User(models.Model):
    username=models.CharField(max_length=50,unique=True)
    password=models.CharField(max_length=25)
    email=models.EmailField(max_length=100)
    phone=models.BigIntegerField()
    address=models.CharField(max_length=200)
    is_email_verified = models.BooleanField(default=False)  # Track email verification
    email_verification_token = models.CharField(max_length=100, null=True, blank=True)  # Store OTP or token
    profile_photo = models.ImageField(upload_to='profile_photos/', null=True, blank=True)  # Add this field
    
class Product(models.Model):
    name = models.CharField(max_length=255)  # Name of the item
    description = models.CharField(max_length=100)         # Detailed description
    price = models.IntegerField(default=100)  # Price with two decimal places
    stock = models.PositiveIntegerField(default=1)  # Number of available items
    category = models.CharField(max_length=100)  # Optional category field
    image1 = models.CharField(max_length=100)  # Image upload field
    image2 = models.CharField(max_length=100,null=True, blank=True)
    image3 = models.CharField(max_length=100,null=True, blank=True)
        
    def __str__(self):
        return self.name
 
 
    
class Order(models.Model):
    PENDING = 'PENDING'
    COMPLETED = 'COMPLETED'
    CANCELLED = 'CANCELLED'
    
    ORDER_STATUS_CHOICES = [
        (PENDING, 'Pending'),
        (COMPLETED, 'Completed'),
        (CANCELLED, 'Cancelled'),
    ]

    session_id = models.CharField(max_length=255, blank=True, null=True)  # Link to the user placing the order
    shipping_address = models.TextField()  # Shipping address for the order
    status = models.CharField(max_length=10, choices=ORDER_STATUS_CHOICES, default=PENDING)  # Order status
    total_amount = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)  # Total order price
    created_at = models.DateTimeField(auto_now_add=True)  # Timestamp for when the order was created
    updated_at = models.DateTimeField(auto_now=True)  # Timestamp for when the order was last updated

    def __str__(self):
        return f"Order {self.id} - Session {self.session_id}"

    def update_total_amount(self):
        """Recalculate the total amount for the order."""
        total = sum(item.get_total_price() for item in self.order_items.all())
        self.total_amount = total
        self.save()

# OrderItem Model - stores the details of each product in an order
class OrderItem(models.Model):
    order = models.ForeignKey(Order, related_name='order_items', on_delete=models.CASCADE)  # Link to the Order
    product = models.ForeignKey(Product, on_delete=models.CASCADE)  # Link to the Product
    quantity = models.PositiveIntegerField()  # Quantity of the product in the order
    unit_price = models.DecimalField(max_digits=10, decimal_places=2)  # Price of a single product at the time of the order

    def __str__(self):
        return f"{self.quantity} x {self.product.name}"

    def get_total_price(self):
        """Calculate the total price for this order item (quantity * unit_price)."""
        return self.quantity * self.unit_price
 
 
 
    

class EwasteRequest(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    name = models.CharField(max_length=255)
    address = models.TextField()
    contact = models.CharField(max_length=10)
    items = models.TextField()
    preferred_date = models.DateField()
    status = models.CharField(
        max_length=20,
        choices=[('Pending', 'Pending'), ('Completed', 'Completed')],
        default='Pending'
    )
    def __str__(self):
        return f"{self.name} - {self.items}"


class Wishlist(models.Model):
    product = models.ForeignKey(Product,on_delete=models.CASCADE)
    user = models.ForeignKey(User,on_delete=models.CASCADE)
    quantity = models.PositiveIntegerField(default=1)
    
    @property
    def total_price(self):
        """Calculate the total price for this cart item."""
        return self.quantity * self.product.price
  


class Feedback(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)  # Reference to User model
    feedback_text = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)  # Automatically set when created

    def __str__(self):
        return f"Feedback from {self.user.username} at {self.created_at}"

class OTPVerification(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    otp = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    attempt_count = models.PositiveIntegerField(default=0)
    is_expired = models.BooleanField(default=False)

    def is_otp_expired(self):
        """Check if the OTP has expired (e.g., after 5 minutes)."""
        return timezone.now() > self.created_at + timedelta(minutes=5)