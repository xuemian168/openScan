from django import forms

class CSVUploadForm(forms.Form):
    csv_file = forms.FileField(label="上传CSV文件")
