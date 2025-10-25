from flask_wtf import FlaskForm
# FIX: Added SubmitField to the import list
from wtforms import StringField, FloatField, TextAreaField, SelectField, SubmitField 
from wtforms.validators import DataRequired, Length, Regexp

class TransactionForm(FlaskForm):
    amount = FloatField('Amount', validators=[DataRequired()])
    recipient = StringField('Recipient', validators=[DataRequired(), Length(max=150)])
    notes = TextAreaField('Notes', validators=[DataRequired(), Length(max=1000)])
    status = SelectField('Status', choices=[('pending', 'Pending'), ('completed', 'Completed'), ('failed', 'Failed')])
    
    # CRITICAL ADDITION: TOTP code for transaction authorization
    totp_code = StringField('Live TOTP Code (from Authenticator App)', 
                            validators=[DataRequired(), Length(min=6, max=6), Regexp(r'^\d+$', message="TOTP must be digits only")])
                            
    submit = SubmitField('Send')