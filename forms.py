from flask_wtf import FlaskForm
from wtforms import StringField, FloatField, TextAreaField, SubmitField 
from wtforms.validators import DataRequired, Length, Regexp, NumberRange

class TransactionForm(FlaskForm):
    """
    Form for customers to initiate transfers.
    The 'status' field has been removed to ensure the ledger is 
    system-controlled and prevents user tampering.
    """
    amount = FloatField('Amount', validators=[
        DataRequired(),
        NumberRange(min=0.01, message="Amount must be greater than zero.")
    ])
    
    recipient = StringField('Recipient', validators=[
        DataRequired(), 
        Length(max=150)
    ])
    
    notes = TextAreaField('Notes', validators=[
        DataRequired(), 
        Length(max=1000)
    ])
    
    # STATUS FIELD REMOVED: Status is now automatically set to 'COMPLETED' 
    # in the backend logic (app.py) after successful mining.

    totp_code = StringField('Live TOTP Code (from Authenticator App)', 
                            validators=[
                                DataRequired(), 
                                Length(min=6, max=6), 
                                Regexp(r'^\d+$', message="TOTP must be digits only")
                            ])
                            
    submit = SubmitField('Send')

# Admin Credit action (set_initial_balance) ---
class InitialBalanceForm(FlaskForm):
    """Form used by the Admin to manually credit a new user's wallet."""
    amount = FloatField('Amount to Credit (₹)', 
                        validators=[
                            DataRequired(), 
                            NumberRange(min=1.00, message='Amount must be a positive value.')
                        ])
    
    submit = SubmitField('Set Initial Balance')