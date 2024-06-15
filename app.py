import streamlit as st
import pandas as pd
import io
import msoffcrypto

# Define the correct password
CORRECT_PASSWORD = "9167546776"

# Function to check allowed file types
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() == 'xlsx'

# Function to decrypt and read Excel file
def decrypt_excel(file, password=None):
    try:
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
        st.warning(f"Decryption failed or not needed: {e}")
        try:
            return pd.read_excel(file)  # Attempt to read without decryption
        except Exception as e:
            st.error(f"Error reading Excel file: {e}")
            return None

# Normalize SEATNO to a fixed length with leading zeros
def normalize_seatno(df, length=10):
    df['SEATNO'] = df['SEATNO'].astype(str).str.zfill(length)
    return df

# Ensure the merge keys are present and have the same data type
def prepare_dataframe(df):
    df = normalize_seatno(df)
    if 'Subjectcode' in df.columns:
        df['Subjectcode'] = df['Subjectcode'].astype(str)
    else:
        st.error("Column 'Subjectcode' not found in one of the files.")
        return None
    if 'FINALMARKS' not in df.columns:
        st.error("Column 'FINALMARKS' not found in one of the files.")
        return None
    return df

st.title('Excel File Comparison App')

# Password verification
if 'password_verified' not in st.session_state:
    st.session_state['password_verified'] = False

if not st.session_state['password_verified']:
    password = st.text_input("Enter the password to access the app", type="password")
    if st.button("Verify"):
        if password == CORRECT_PASSWORD:
            st.session_state['password_verified'] = True
            st.success("Password verified! You can now access the app.")
        else:
            st.error("Incorrect password. Please try again.")
else:
    # Upload files
    file1 = st.file_uploader("Upload first Excel file", type="xlsx")
    password1 = st.text_input("Password for first file (leave blank if not encrypted)", type="password")
    file2 = st.file_uploader("Upload second Excel file", type="xlsx")
    password2 = st.text_input("Password for second file (leave blank if not encrypted)", type="password")

    if st.button("Compare Files"):
        progress_bar = st.progress(0)
        status_text = st.empty()

        if file1 and file2 and allowed_file(file1.name) and allowed_file(file2.name):
            status_text.text("Decrypting and reading first file...")
            progress_bar.progress(10)
            df1 = decrypt_excel(file1, password1)
            
            status_text.text("Decrypting and reading second file...")
            progress_bar.progress(30)
            df2 = decrypt_excel(file2, password2)

            if df1 is not None and df2 is not None:
                status_text.text("Preparing dataframes...")
                progress_bar.progress(50)
                df1 = prepare_dataframe(df1)
                df2 = prepare_dataframe(df2)

                if df1 is not None and df2 is not None:
                    status_text.text("Merging dataframes...")
                    progress_bar.progress(70)
                    # Merge the dataframes on SEATNO and Subjectcode
                    merged_df = pd.merge(df1, df2, on=['SEATNO', 'Subjectcode'], suffixes=('_file1', '_file2'))
                    
                    status_text.text("Comparing FINALMARKS...")
                    progress_bar.progress(90)
                    # Check for differences in FINALMARKS
                    changes = merged_df[merged_df['FINALMARKS_file1'] != merged_df['FINALMARKS_file2']]
                    
                    progress_bar.progress(100)
                    if changes.empty:
                        st.success("No changes detected between the two files.")
                    else:
                        st.subheader("Changes Detected")
                        st.write(changes)
                else:
                    st.error("Preparation of one or both dataframes failed.")
            else:
                st.error("Could not decrypt or read one or both files.")
        else:
            st.error("Invalid file format or no file uploaded.")
