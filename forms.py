from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, FloatField, TextAreaField, SelectField
from wtforms.validators import DataRequired, Email, EqualTo, Length

class TransactionForm(FlaskForm):
    amount = FloatField('Amount', validators=[DataRequired()])
    recipient = StringField('Recipient', validators=[DataRequired(), Length(max=150)])
    notes = TextAreaField('Notes', validators=[DataRequired(), Length(max=1000)])
    status = SelectField('Status', choices=[('pending', 'Pending'), ('completed', 'Completed'), ('failed', 'Failed')])
    submit = SubmitField('Send')