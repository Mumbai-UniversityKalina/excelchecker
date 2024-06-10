from flask import Flask, render_template, request
import pandas as pd
import os
import io
import msoffcrypto
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50 MB

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() == 'xlsx'

def save_chunks(file):
    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)
    return filepath

def decrypt_excel(file_path, password):
    try:
        with open(file_path, "rb") as file:
            office_file = msoffcrypto.OfficeFile(file)
            if password:
                office_file.load_key(password=password)
            else:
                office_file.load_key()  # Attempt to open without password
            decrypted_stream = io.BytesIO()
            office_file.decrypt(decrypted_stream)
            decrypted_stream.seek(0)
            return pd.read_excel(decrypted_stream)
    except Exception as e:
        print(f"Error processing Excel file: {e}")
        return pd.read_excel(file_path)  # Attempt to read without decryption

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        file1 = request.files.get('file1')
        file2 = request.files.get('file2')
        password1 = request.form.get('password1', '')
        password2 = request.form.get('password2', '')

        if file1 and file2 and allowed_file(file1.filename) and allowed_file(file2.filename):
            filepath1 = save_chunks(file1)
            filepath2 = save_chunks(file2)

            df1 = decrypt_excel(filepath1, password1)
            df2 = decrypt_excel(filepath2, password2)

            if df1 is not None and df2 is not None:
                df1.set_index('SEATNO', inplace=True)
                df2.set_index('SEATNO', inplace=True)
                df1_changes = df1[df1['FINALMARKS'] != df2['FINALMARKS']]
                df2_changes = df2[df1['FINALMARKS'] != df2['FINALMARKS']]
                if df1_changes.empty and df2_changes.empty:
                    return render_template('no_changes.html')
                return render_template('changes.html', changes1=df1_changes.to_html(classes='data'),
                                       changes2=df2_changes.to_html(classes='data'))
            else:
                return render_template('error.html', error="Could not decrypt or read one or both files.")
        else:
            return render_template('error.html', error="Invalid file format or no file uploaded.")
    return render_template('index.html')


@app.errorhandler(Exception)
def handle_exception(error):
    """Handle unexpected exceptions."""
    return render_template('error.html', error=str(error)), 500


if __name__ == '__main__':
    app.run(debug=True)