from django import forms
from scanner.models import Scanner


class ScannerForm(forms.ModelForm):
    class Meta:
        model = Scanner
        fields = []
        widgets = {
         
            'ipaddress': forms.TextInput(attrs={
                "class":"form-control"
            }),
            
        }
    