import streamlit as st
import pandas as pd
import io
import msoffcrypto

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

# Remove duplicates based on SEATNO
def remove_duplicates(df):
    return df[~df.index.duplicated(keep='first')]

st.title('Excel File Comparison App')

# Upload files
file1 = st.file_uploader("Upload first Excel file", type="xlsx")
password1 = st.text_input("Password for first file (leave blank if not encrypted)", type="password")
file2 = st.file_uploader("Upload second Excel file", type="xlsx")
password2 = st.text_input("Password for second file (leave blank if not encrypted)", type="password")

if st.button("Compare Files"):
    if file1 and file2 and allowed_file(file1.name) and allowed_file(file2.name):
        df1 = decrypt_excel(file1, password1)
        df2 = decrypt_excel(file2, password2)

        if df1 is not None and df2 is not None:
            df1 = normalize_seatno(df1)
            df2 = normalize_seatno(df2)
            df1.set_index('SEATNO', inplace=True)
            df2.set_index('SEATNO', inplace=True)

            # Remove duplicates
            df1 = remove_duplicates(df1)
            df2 = remove_duplicates(df2)

            # Reindex df2 to match df1
            df2 = df2.reindex(df1.index)

            df1_changes = df1[df1['FINALMARKS'] != df2['FINALMARKS']]
            df2_changes = df2[df1['FINALMARKS'] != df2['FINALMARKS']]
            
            if df1_changes.empty and df2_changes.empty:
                st.success("No changes detected between the two files.")
            else:
                st.subheader("Changes in First File")
                st.write(df1_changes)
                st.subheader("Changes in Second File")
                st.write(df2_changes)
        else:
            st.error("Could not decrypt or read one or both files.")
    else:
        st.error("Invalid file format or no file uploaded.")
