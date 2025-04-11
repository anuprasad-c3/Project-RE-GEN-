from datetime import datetime
from smtplib import SMTPException 
from django.shortcuts import redirect, render,get_object_or_404
from django.contrib import messages
from django.core.mail import send_mail
import random
from django.conf import settings
from django.http import HttpResponse, JsonResponse 
from .models import * 
from django.urls import reverse
from django.core.files.storage import FileSystemStorage
from django.template import loader 
from django.views.decorators.cache import never_cache
from django.contrib.auth.decorators import login_required
from .forms import ProductForm 
from django.core.exceptions import ValidationError
import re
from io import BytesIO
from django.core.files.storage import default_storage
import pandas as pd
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib import colors

def index(request):
    return render(request, 'Ewaste_app/front.html')

def home(request):
    user_data = None

    if 'USER_ID' in request.session:
        user_id = request.session['USER_ID']
        user_data = User.objects.get(id=user_id)  # Fetch user details

    return render(request, 'Ewaste_app/home.html', {'user': user_data})

def upload_profile_photo(request):
    if 'USERSESSION' not in request.session:
        messages.error(request, 'You must be logged in to upload a profile photo.')
        return redirect('UserLogin')  # Redirect to login if the user is not logged in

    if request.method == 'POST':
        profile_photo = request.FILES.get('profile_photo')
        if profile_photo:
            user_id = request.session.get('USER_ID')
            try:
                user = User.objects.get(id=user_id)
                # Delete the old profile photo if it exists
                if user.profile_photo:
                    default_storage.delete(user.profile_photo.path)
                # Save the new profile photo
                user.profile_photo = profile_photo
                user.save()
                messages.success(request, 'Profile photo updated successfully!')
            except User.DoesNotExist:
                messages.error(request, 'User not found.')
        else:
            messages.error(request, 'No file selected.')
        return redirect('home')  # Redirect to the profile page
    return render(request, 'Ewaste_app/home.html')

def user_edit(request, user_id):
    user = get_object_or_404(User, id=user_id)
    if request.method == 'POST':
        user.username = request.POST.get('username')
        user.email = request.POST.get('email')
        user.save()
        return redirect('home')

    return render(request, 'Ewaste_app/edit_user.html', {'user': user})

def registration(request):
    return render(request, 'Ewaste_app/registration.html')

def adminLogin(request):
    template = loader.get_template('Ewaste_app/adm-login.html')
    context = {}
    
    # Hardcoded admin credentials
    admin_username = "liya"
    admin_password = "123"
    
    if request.method == "POST":
        username = request.POST.get('txtuname')
        password = request.POST.get('txtpassword')
        
        # Check hardcoded credentials
        if username == admin_username and password == admin_password:
            request.session['USERNAME'] = username  # Store session for logged-in admin
            template = loader.get_template('Ewaste_app/admin-login.html')
            return HttpResponse(template.render({}, request))
        else:
            context = {"error": "Invalid username or password"}
    
    return HttpResponse(template.render(context,request))
  
@login_required
@never_cache
def logout_view(request): 
    if 'USERNAME' in request.session:
        del request.session['USERNAME']  
    request.session.flush()  
    return redirect('index')  

def userloginpage(request):
    return render(request,"Ewaste_app/user-login.html")

def UserLogin(request):
    
    context = {}
    if request.method == "POST":
        username = request.POST.get('txtUname')
        password = request.POST.get('txtPassword')
        
        # Check if the user exists and validate the password
        try:
            user_obj = User.objects.get(username=username)
            if user_obj.password == password:
                request.session['USERSESSION'] = user_obj.username
                request.session['USER_ID'] = user_obj.id
                return redirect('home')  # Redirect to the attendance list page after login
            else:
                context = {"error": "Invalid password"}
        except User.DoesNotExist:
            context = {"error": "Invalid user"}
    
    return render(request,'Ewaste_app/user-login.html',context)

def register(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')

        # Check if username or email already exists
        if User.objects.filter(username=username).exists():
            error = "Username already exists. Please choose a different username."
            return render(request, 'Ewaste_app/registration.html', {'error': error})

        if User.objects.filter(email=email).exists():
            error = "Email already registered. Try logging in."
            return render(request, 'Ewaste_app/registration.html', {'error': error})

        # Store user details in session
        request.session['user_data'] = {
            'username': username,
            'password': request.POST.get('password'),  # Hash before saving
            'email': email,
            'phone': request.POST.get('phone-number'),
            'address': request.POST.get('address')
        }

        # Generate OTP
        otp = str(random.randint(100000, 999999))  # 6-digit OTP
        request.session['otp'] = otp

        # Send OTP via email
        subject = 'Email Verification OTP'
        message = f'Your OTP for email verification is: {otp}'
        email_from = settings.EMAIL_HOST_USER
        recipient_list = [email]
        send_mail(subject, message, email_from, recipient_list)

        # Redirect to OTP verification page
        return redirect('verify_email')

    return render(request, 'Ewaste_app/registration.html')

def verify_email(request):
    # Check if session data exists
    if 'user_data' not in request.session or 'otp' not in request.session:
        messages.error(request, "Session expired. Please register again.")
        return redirect('register')

    user_data = request.session.get('user_data')
    correct_otp = request.session.get('otp')

    # Set attempt count in session (if not already set)
    if 'otp_attempts' not in request.session:
        request.session['otp_attempts'] = 0

    if request.method == 'POST':
        otp = request.POST.get('otp')

        # Check attempt limit
        if request.session['otp_attempts'] >= 3:
            messages.error(request, "Too many failed attempts. OTP expired. Please request a new OTP.")
            del request.session['user_data']
            del request.session['otp']
            del request.session['otp_attempts']
            return redirect('register')

        if otp == correct_otp:
            # Create and save user after successful OTP verification
            new_user = User.objects.create(
                username=user_data['username'],
                email=user_data['email'],
                password=user_data['password'],  # Hash before saving
                phone=user_data['phone'],
                address=user_data['address'],
                is_email_verified=True  # Mark email as verified
            )

            # Clear session data
            del request.session['user_data']
            del request.session['otp']
            del request.session['otp_attempts']

            messages.success(request, "Email verified! You can now log in.")
            return redirect('UserLogin')

        else:
            # Increment attempt count
            request.session['otp_attempts'] += 1
            request.session.modified = True  # Ensure session updates

            remaining_attempts = 3 - request.session['otp_attempts']
            messages.error(request, f"Invalid OTP. You have {remaining_attempts} attempts remaining.")

            return render(request, 'Ewaste_app/verify_email.html')

    return render(request, 'Ewaste_app/verify_email.html')


def resend_otp(request):
    # Check if session data exists
    if 'user_data' not in request.session:
        messages.error(request, "Session expired. Please register again.")
        return redirect('register')

    # Generate a new OTP
    otp = str(random.randint(100000, 999999)) 
    request.session['otp'] = otp

    # Send the new OTP via email
    subject = 'New OTP for Email Verification'
    message = f'Your new OTP for email verification is: {otp}'
    email_from = settings.EMAIL_HOST_USER
    recipient_list = [request.session['user_data']['email']]
    send_mail(subject, message, email_from, recipient_list)

    messages.success(request, "A new OTP has been sent to your email.")
    return redirect('verify_email')

def dashboard(request):
    # Check if the user is logged in using the session
    if 'USERSESSION' in request.session:
        # Retrieve the username from the session
        username = request.session['USERSESSION']
        
        # Filter requests associated with the logged-in user
        pickup_requests = EwasteRequest.objects.filter(user__username=username)
        
        # Render the dashboard with filtered requests
        return render(request, 'Ewaste_app/dashboard.html', {'pickup_requests': pickup_requests})
    else:
        # Redirect to login if the session is not found
        return redirect('UserLogin')  # Replace 'user_login' with the correct URL name for your login view

def validate_email(email):
    """Validate email format."""
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_regex, email):
        raise ValidationError('Invalid email address.')

def contact(request):
    if request.method == 'POST':
        name = request.POST.get('name')
        email = request.POST.get('email')
        message = request.POST.get('message')

        # Validate input
        if not name or not email or not message:
            messages.error(request, 'All fields are required.')
            return redirect('contact')

        try:
            validate_email(email)  # Validate email format

            # Send email
            send_mail(
                f'Contact Form Submission from {name}',
                f'From: {email}\n\nMessage:\n{message}',
                settings.EMAIL_HOST_USER,
                [settings.EMAIL_HOST_USER],
                fail_silently=False,
            )
            messages.success(request, 'Your message has been sent. We will get back to you soon!')
        except ValidationError as e:
            messages.error(request, str(e))
        except Exception as e:
            messages.error(request, f"Error sending email: {e}")

        return redirect('contact')

    return render(request, 'Ewaste_app/contact.html')

def login_call(request):
    return render(request,"Ewaste_app/login.html")

def add(request):
    return render(request,"Ewaste_app/add-item.html")

def user_awareness(request):
    return render(request,"Ewaste_app/user-awareness.html")

def added_item(req):
    if req.method == 'POST':
        # Get form data
        name = req.POST["itemName"]
        description = req.POST["itemDescription"]
        price = req.POST["itemPrice"]
        category = req.POST["itemCategory"]
        stock = req.POST["itemStock"]  # 🟢 Get stock input

        # Get files
        myFile1 = req.FILES.get('itemImage1')
        myFile2 = req.FILES.get('itemImage2')
        myFile3 = req.FILES.get('itemImage3')

        # File handling
        fs = FileSystemStorage()

        file_name1 = str(datetime.timestamp(datetime.now())) + myFile1.name if myFile1 else ''
        file_name2 = str(datetime.timestamp(datetime.now())) + myFile2.name if myFile2 else ''
        file_name3 = str(datetime.timestamp(datetime.now())) + myFile3.name if myFile3 else ''

        if myFile1:
            fs.save(file_name1, myFile1)
        if myFile2:
            fs.save(file_name2, myFile2)
        if myFile3:
            fs.save(file_name3, myFile3)

        # Save in database
        product = Product(
            name=name,
            description=description,
            category=category,
            price=price,
            stock=stock,  
            image1=file_name1,
            image2=file_name2,
            image3=file_name3,
        ) 
        product.save()

        return redirect('itemview')

    return render(req, 'Ewaste_app/admin-item.html')
   
def product_list(request):
    products = Product.objects.all()
    return render(request, 'Ewaste_app/admin-item.html', {'prd': products})

def admin_ui(request):
    return render(request,"Ewaste_app/adm-login.html")

def work(request):
    return render(request, 'Ewaste_app/how-work.html')

def adminDash(request):
    user_count = User.objects.count()
    return render(request, 'Ewaste_app/admin-login.html',{'user_count': user_count})

def itemview(request):
    allitem=Product.objects.all()
    return render(request,"Ewaste_app/admin-item.html",{'product':allitem})

def edit_product(request, product_id):
    product = get_object_or_404(Product, id=product_id)
    
    if request.method == 'POST':
        form = ProductForm(request.POST, request.FILES, instance=product)
        if form.is_valid():
            form.save()
            return redirect('itemview')  # Redirect to the product list page after editing
    else:
        form = ProductForm(instance=product)
    
    return render(request, 'Ewaste_app/edit_product.html', {'form': form, 'product': product})

def deleteprd(request, pid): 
    try:
        fu = get_object_or_404(Product, id=pid)
        fs = FileSystemStorage()
        if fu.image1 and fs.exists(fu.image1): 
            fs.delete(fu.image1)
        
        fu.delete()
        return redirect('adminDash')
    except Exception as e:
        return HttpResponse(f"Error: {e}",status=500)

def manage_users(request):
    users = User.objects.all()
    return render(request, 'Ewaste_app/manage_user.html', {'users': users})

def edit_user(request, user_id):
    user = get_object_or_404(User, id=user_id)
    if request.method == 'POST':
        user.username = request.POST.get('username')
        user.email = request.POST.get('email')
        user.save()
        return redirect('manage_users')

    return render(request, 'Ewaste_app/edit_user.html', {'user': user})

def delete_user(request, user_id):
    # Delete the selected user
    user = get_object_or_404(User, id=user_id)
    user.delete()
    return redirect('manage_users')

def req_pickup(request):
    return render(request, 'Ewaste_app/request-pickup.html')

def user_itemview(request):
    products = Product.objects.all()
    user = request.user
    if user.is_authenticated: context = { 'product': products, 'username': user.username, 'email': user.email, 'address': user.address, # Use the address field from the User model 
                                         }
    else: context = { 'product': products, }
    return render(request, 'Ewaste_app/user-list-view.html', context) 

def request_pickup(request):
    # Check if user is authenticated using session variable
    if 'USERSESSION' not in request.session:
        # If not logged in, redirect to login page
        messages.error(request, "You must be logged in to request a pickup.")
        return redirect('login')  # Adjust 'login' to your actual login URL name
    
    if request.method == "POST":
        name = request.POST.get('name')
        address = request.POST.get('address')
        contact = request.POST.get('contact')
        items = request.POST.get('items')
        preferred_date = request.POST.get('preferred_date', None)

        # Check if all required fields are filled
        if not all([name, address, contact, items, preferred_date]):
            messages.error(request, "Please fill out all fields.")
            return render(request, 'Ewaste_app/request-pickup.html')

        # Get the logged-in user's username from session and fetch User object
        username = request.session['USERSESSION']
        user_obj = User.objects.get(username=username)
        

        # Save directly to the model with the fetched user
        EwasteRequest.objects.create(
            user=user_obj,  # Use the user object fetched from session
            name=name,
            address=address,
            contact=contact,
            items=items,
            preferred_date=preferred_date,
        )
        messages.success(request, "Request submitted successfully!")
        return redirect('dashboard')

    # If it's a GET request, fetch only the requests created by the logged-in user
    username = request.session.get('USERSESSION')
    user_obj = User.objects.get(username=username)
    user_requests = EwasteRequest.objects.filter(user=user_obj)
    total_requests = EwasteRequest.objects.filter(user=user_obj).count()
    
    context = {
        'user_requests': user_requests,
        'total_requests': total_requests
    }
    return render(request, 'Ewaste_app/request-pickup.html', context)

def update_cart_quantity(request, cart_item_id, quantity):
    cart_item = get_object_or_404(Wishlist, id=cart_item_id, user=request.user)
    
    if quantity > 0:
        cart_item.quantity = quantity
        cart_item.save()
    else:
        cart_item.delete()

    return redirect('view_cart')

def admin_report(request):
    requests = EwasteRequest.objects.all()
    return render(request, 'Ewaste_app/admin-report.html', {'requests': requests})

def filter_reports(request):
    if request.method == 'GET':
        selected_month = request.GET.get('month')
        if selected_month:
            try:
                year, month = map(int, selected_month.split('-'))
                reports = EwasteRequest.objects.filter(
                    preferred_date__year=year,
                    preferred_date__month=month
                )
                return render(request, 'admin_report.html', {'reports': reports, 'selected_month': selected_month})
            except (ValueError, IndexError):
                # Handle invalid month format
                return render(request, 'admin_report.html', {'reports': [], 'selected_month': None, 'error': 'Invalid month format'})
        else:
            # If no month is selected, show all reports
            reports = EwasteRequest.objects.all()
            return render(request, 'admin_report.html', {'reports': reports, 'selected_month': None})
    return render(request, 'admin_report.html', {'reports': [], 'selected_month': None})

def export_reports(request):
    selected_month = request.GET.get('month')
    export_format = request.GET.get('format', 'pdf')  # Default to PDF

    if selected_month:
        try:
            year, month = map(int, selected_month.split('-'))
            reports = EwasteRequest.objects.filter(
                preferred_date__year=year,
                preferred_date__month=month
            ).values('id', 'name', 'address', 'contact', 'items', 'status', 'preferred_date')

            if not reports:
                return HttpResponse("No reports found for the selected month.")

            if export_format == 'pdf':
                # Create a buffer for the PDF
                buffer = BytesIO()

                # Create the PDF object
                pdf = SimpleDocTemplate(buffer, pagesize=letter)
                styles = getSampleStyleSheet()
                story = []

                # Add a title
                title = f"E-Waste Reports for {selected_month}"
                story.append(Paragraph(title, styles['Title']))
                story.append(Spacer(1, 12))  # Add some space

                # Add report details
                for report in reports:
                    # Format the report details
                    report_text = (
                        f"<b>ID:</b> {report['id']}<br/>"
                        f"<b>Name:</b> {report['name']}<br/>"
                        f"<b>Address:</b> {report['address']}<br/>"
                        f"<b>Contact:</b> {report['contact']}<br/>"
                        f"<b>Items:</b> {report['items']}<br/>"
                        f"<b>Status:</b> {report['status']}<br/>"
                        f"<b>Preferred Date:</b> {report['preferred_date']}<br/>"
                    )
                    story.append(Paragraph(report_text, styles['BodyText']))
                    story.append(Spacer(1, 12))  # Add space between reports

                # Build the PDF
                pdf.build(story)

                # Prepare the response
                buffer.seek(0)
                response = HttpResponse(buffer, content_type='application/pdf')
                response['Content-Disposition'] = f'attachment; filename="ewaste_reports_{selected_month}.pdf"'
                return response

        except (ValueError, IndexError):
            return HttpResponse("Invalid month format.")
    else:
        return HttpResponse("No month selected.")

def update_status(request, order_id, status):
    # Validate the status
    if status not in ['Completed', 'Cancelled']:
        messages.error(request, 'Invalid status update.')
        return redirect('admin_orders')  # Redirect back to the order list
    
    # Retrieve the order
    ewasterequest = get_object_or_404(EwasteRequest, id=order_id)

    # Update the status
    ewasterequest.status = status
    ewasterequest.save()

    # Display a success message
    messages.success(request, f"Order {order_id} marked as {status}.")

    # Redirect back to the order list
    return redirect('admin_report')

def us_productdetail(request, product_id):
    # Fetch the product by ID or show 404 error if not found
    product = get_object_or_404(Product,id=product_id)

    # Context for the product details template
    context = {
        'product': product,
    }

    return render(request,'Ewaste_app/user-product-detail.html',context)

def add_to_wishlist(request, product_id):
    # Check if the user is logged in
    if 'USERSESSION' not in request.session:
        return redirect('user-login')  # Redirect to login page if not logged in

    try:
        user_obj = User.objects.get(username=request.session['USERSESSION'])
    except User.DoesNotExist:
        return redirect('user-login')

    try:
        product_obj = Product.objects.get(id=product_id)
    except Product.DoesNotExist:
        messages.error(request, "Product not found.")
        return redirect('home') 

    
    if not Wishlist.objects.filter(user=user_obj, product=product_obj).exists():
        # Add product to wishlist
        Wishlist.objects.create(user=user_obj, product=product_obj)
        messages.success(request, "Product added to your wishlist.")
    else:
        messages.info(request, "Product already in your wishlist.")

    return redirect('view_cart')  

def view_cart(request):
    if 'USERSESSION' not in request.session:
        print("No USERSESSION found.")
        return redirect('user-login')

    try:
        user_obj = User.objects.get(username=request.session['USERSESSION'])
        print("User found:", user_obj)
    except User.DoesNotExist:
        print("User does not exist.")
        return redirect('user-login')

    # Fetch cart items
    cart_items = Wishlist.objects.filter(user=user_obj)
    total_price = sum(item.total_price for item in cart_items)
    print("Wishlist items for user:", list(cart_items))  # Debug print

    context = {
        'cart_items': cart_items,
        'total_price': total_price,
        'user': user_obj,  # Add the user object here to display profile data
    }

    return render(request, 'Ewaste_app/icart.html', context)

def remove_from_cart(request, cart_item_id):
    if 'USERSESSION' not in request.session:
        return redirect('user-login')

    try:
        user_obj = User.objects.get(username=request.session['USERSESSION'])
    except User.DoesNotExist:
        return redirect('user-login')

    cart_item = get_object_or_404(Wishlist, id=cart_item_id, user=user_obj)
    cart_item.delete()
    return redirect('view_cart')
    
def order(request, product_id):
    # Check if USERSESSION exists in the session
    if 'USERSESSION' not in request.session:
        return redirect('user_login') 
    session_username = request.session['USERSESSION']
    product = get_object_or_404(Product, id=product_id)

    if request.method == 'POST':
        customer_address = request.POST.get('customer_address', '').strip()
        quantity = int(request.POST.get('quantity', 0))

        if quantity <= 0:
            return render(request, 'Ewaste_app/order_page.html', {
                'product': product,
                'error': 'Quantity must be greater than zero.'
            })

        # Check if stock is available
        if product.stock < quantity:
            return render(request, 'Ewaste_app/order_page.html', {
                'product': product,
                'error': 'Sorry, only {} items are available in stock.'.format(product.stock)
            })

        # Create the order
        order = Order.objects.create(
            session_id=session_username,  # Link the order to the logged-in user
            shipping_address=customer_address
        )
        OrderItem.objects.create(
            order=order,
            product=product,
            quantity=quantity,
            unit_price=product.price 
        )
        product.stock -= quantity
        product.save()
        # Update the order total
        order.update_total_amount()
        # Remove the product from the user's wishlist (if it exists)
        user = User.objects.get(username=session_username)
        Wishlist.objects.filter(user=user, product=product).delete()

        return redirect('order_success', order_id=order.id)

    return render(request, 'Ewaste_app/order_page.html', {'product': product})

def export_orders(request):
    selected_month = request.GET.get('month')
    export_format = request.GET.get('format', 'csv')

    if not selected_month:
        orders = Order.objects.all().prefetch_related('order_items__product')
    else:
        year, month = map(int, selected_month.split('-'))
        orders = Order.objects.filter(
            created_at__year=year,
            created_at__month=month
        ).prefetch_related('order_items__product')

    if not orders.exists():
        return HttpResponse("No orders found for the selected criteria.", status=404)

    if export_format == 'csv':
        data = []
        for order in orders:
            products = ", ".join([f"{item.product.name} (x{item.quantity})" for item in order.order_items.all()])
            data.append({
                'ID': order.id,
                'User': order.session_id,
                'Products': products,
                'Total': order.total_amount,
                'Status': order.status,
                'Date': order.created_at
            })
        df = pd.DataFrame(data)
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = f'attachment; filename="orders_{selected_month or "all"}.csv"'
        df.to_csv(response, index=False)
        return response

    elif export_format == 'pdf':
        # Create a buffer for the PDF
        buffer = BytesIO()

        # Create the PDF object
        pdf = SimpleDocTemplate(buffer, pagesize=letter)
        styles = getSampleStyleSheet()

        # Title
        title = Paragraph(f"Orders Report - {selected_month or 'All Time'}", styles['Title'])

        # Table data
        data = [['Order ID', 'User', 'Products', 'Total Price', 'Status', 'Created At']]
        for order in orders:
            products = ", ".join([f"{item.product.name} (x{item.quantity})" for item in order.order_items.all()])
            data.append([
                str(order.id),
                order.session_id,
                products,
                f"${order.total_amount}",
                order.status,
                order.created_at.strftime('%Y-%m-%d %H:%M:%S')
            ])

        # Create the table
        table = Table(data)
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),  # Header row background
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),  # Header row text color
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),  # Center align all cells
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),  # Header row font
            ('FONTSIZE', (0, 0), (-1, 0), 12),  # Header row font size
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),  # Header row padding
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),  # Table body background
            ('GRID', (0, 0), (-1, -1), 1, colors.black),  # Add grid lines
            ('FONTSIZE', (0, 1), (-1, -1), 10),  # Table body font size
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),  # Vertical alignment
        ]))

        # Build the PDF
        elements = [title, Spacer(1, 12), table]  # Add space between title and table
        pdf.build(elements)

        # File response
        buffer.seek(0)
        response = HttpResponse(buffer, content_type='application/pdf')
        response['Content-Disposition'] = f'attachment; filename="orders_{selected_month or "all"}.pdf"'
        return response

    return HttpResponse("Invalid export format.", status=400)

def check_low_stock():
    low_stock_products = Product.objects.filter(stock__lt=5)
    if low_stock_products.exists():
        print("Warning: Some products are running low on stock!")

def my_orders(request):
    session_id = request.session.get('USERSESSION')  # Retrieve session_id from the session
    if session_id:
        # Fetch all orders related to the session_id where all OrderItems have a valid product
        user_orders = Order.objects.filter(
            session_id=session_id,
            order_items__product__isnull=False
        ).distinct().prefetch_related('order_items__product')

        return render(request, 'Ewaste_app/my_orders.html', {'user_orders': user_orders})
    else:
        return render(request, 'Ewaste_app/my_orders.html', {'error': 'You are not logged in.'})

def order_success(request, order_id):
    # Retrieve the order using the order_id
    order = get_object_or_404(Order, id=order_id)
    
    # Get all order items related to this order
    order_items = order.order_items.all()

    # Calculate the total price by summing the total price of all order items
    total_price = sum(item.get_total_price() for item in order_items)

    # Pass the order details and total price to the template
    return render(request, 'Ewaste_app/order_success.html', {
        'order': order,
        'order_items': order_items,
        'total_price': total_price
    })

def admin_orders(request):
    # Fetch all orders from the database
    orders = Order.objects.filter(
        order_items__product__isnull=False
    ).distinct().prefetch_related('order_items__product')
    return render(request, 'Ewaste_app/admin_orders.html', {'orders': orders})

def update_order_status(request, order_id, status):
    # Validate the status
    if status not in ['Completed', 'Cancelled']:
        messages.error(request, 'Invalid status update.')
        return redirect('admin_orders')  # Redirect back to the order list
    
    # Retrieve the order
    order = get_object_or_404(Order, id=order_id)

    # Update the status
    order.status = status
    order.save()

    # Display a success message
    messages.success(request, f"Order {order_id} marked as {status}.")

    # Redirect back to the order list
    return redirect('admin_orders')

def submit_feedback(request):
    if 'USERSESSION' not in request.session:  # Check if user is logged in
        return redirect('user_login')  # Redirect to login page if not logged in

    if request.method == 'POST':
        feedback_text = request.POST.get('feedback_text', '').strip()
        username = request.session.get('USERSESSION')  # Retrieve username from session

        try:
            # Retrieve the actual user object from the User model
            user_obj = User.objects.get(username=username)
        except User.DoesNotExist:
            return HttpResponse('user not found.')

        if feedback_text:
            # Save feedback to the database with the actual User object
            Feedback.objects.create(user=user_obj, feedback_text=feedback_text)
            return redirect('feedback_success')
        else:
            return HttpResponse('Feedback cannot be empty.')
    return render(request, 'Ewaste_app/home.html')  # Render the feedback form page

def feedback_success(request):
    return render(request, 'Ewaste_app/feedback_success.html')

def admin_feedback_view(request):
    feedback_list = Feedback.objects.all().order_by('-created_at')  # Newest feedback first
    return render(request, 'Ewaste_app/admin_feedback_page.html', {'feedbacks': feedback_list})

def deleteStd(request, sid): 
    feedback = Feedback.objects.get(id=sid) 
    feedback.delete() 
    return redirect('/admin_feedback_view/')

def about_page(request):
    return render(request, 'Ewaste_app/about.html')

def forgot_password(request):
    if request.method == "POST":
        email = request.POST.get('email')
        user = User.objects.filter(email=email).first()
        if user:
            otp = str(random.randint(100000, 999999))
            OTPVerification.objects.update_or_create(user=user, defaults={'otp': otp})

            # Send OTP via Email
            send_mail(
                'Password Reset OTP',
                f'Your OTP is: {otp}',
                'your-email@gmail.com',  # Replace with your email
                [email],
                fail_silently=False,
            )
            request.session['reset_email'] = email
            return redirect('verify_otp')
    return render(request, 'Ewaste_app/forgot_password.html')

def verify_otp(request):
    email = request.session.get('reset_email')
    if not email:
        return redirect('forgot_password')

    if request.method == "POST":
        otp = request.POST.get('otp')
        user = User.objects.filter(email=email).first()
        otp_record = OTPVerification.objects.filter(user=user, otp=otp).first()
        if otp_record:
            return redirect('reset_password')
    return render(request,'Ewaste_app/verify_otp.html')

def reset_password(request):
    email = request.session.get('reset_email')
    if not email:
        return redirect('forgot_password')

    if request.method == "POST":
        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_password')
        if new_password == confirm_password:
            user = User.objects.filter(email=email).first()
            if user:
                user.password = new_password
                user.save()
                OTPVerification.objects.filter(user=user).delete()
                return redirect('UserLogin')
    return render(request,'Ewaste_app/reset_password.html')
