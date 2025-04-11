from django import forms
from .models import Product

class ProductForm(forms.ModelForm):
    class Meta:
        model = Product
        fields = ['name', 'description', 'price', 'category',  'stock']
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control custom-input', 'placeholder': 'Enter product name'}),
            'description': forms.Textarea(attrs={'class': 'form-control custom-input', 'rows': 3, 'placeholder': 'Enter product description'}),
            'price': forms.NumberInput(attrs={'class': 'form-control custom-input', 'placeholder': 'Enter price'}),
            
            # 'image1': forms.FileInput(attrs={'class': 'form-control custom-file-input'}),
            # 'image2': forms.FileInput(attrs={'class': 'form-control custom-file-input'}),
            # 'image3': forms.FileInput(attrs={'class': 'form-control custom-file-input'}),
            'stock': forms.NumberInput(attrs={'class': 'form-control custom-input', 'placeholder': 'Enter stock quantity'}),
        }
