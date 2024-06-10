from flask import Flask, render_template, request
import pandas as pd
import os
import io
import msoffcrypto

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100 MB

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() == 'xlsx'


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
        return None


@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        # Check if the POST request has the file part
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        # If the user does not select a file, the browser submits an empty file without a filename
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            # Stream the file to disk
            with open(file_path, 'wb') as f:
                while True:
                    chunk = file.stream.read(1024)
                    if not chunk:
                        break
                    f.write(chunk)
            # Process the file here
            return redirect(url_for('success'))
    return render_template('index.html')


@app.errorhandler(Exception)
def handle_exception(error):
    """Handle unexpected exceptions."""
    return render_template('error.html', error=str(error)), 500


if __name__ == '__main__':
    app.run(debug=True)
