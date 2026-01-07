from flask_wtf import FlaskForm
# 🔥TextAreaField is still used by TransactionForm, so it stays
from wtforms import StringField, FloatField, TextAreaField, SelectField, SubmitField 
from wtforms.validators import DataRequired, Length, Regexp, NumberRange

class TransactionForm(FlaskForm):
    amount = FloatField('Amount', validators=[DataRequired()])
    recipient = StringField('Recipient', validators=[DataRequired(), Length(max=150)])
    notes = TextAreaField('Notes', validators=[DataRequired(), Length(max=1000)])
    status = SelectField('Status', choices=[('pending', 'Pending'), ('completed', 'Completed'), ('failed', 'Failed')])
    
    # CRITICAL ADDITION: TOTP code for transaction authorization
    totp_code = StringField('Live TOTP Code (from Authenticator App)', 
                            validators=[DataRequired(), Length(min=6, max=6), Regexp(r'^\d+$', message="TOTP must be digits only")])
                            
    submit = SubmitField('Send')

# --- NEW: Form required for Admin Credit action (set_initial_balance) ---
class InitialBalanceForm(FlaskForm):
    """Form used by the Admin to manually credit a new user's wallet."""
    # Amount must be positive
    amount = FloatField('Amount to Credit (₹)', 
                        validators=[
                            DataRequired(), 
                            NumberRange(min=1.00, message='Amount must be a positive value.')
                        ])
    
    submit = SubmitField('Set Initial Balance')