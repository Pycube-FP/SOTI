import click
from flask.cli import with_appcontext
from app.models import User
from app import db

@click.command('create-admin')
@with_appcontext
def create_admin_command():
    """Create the admin user."""
    admin = User.query.filter_by(email='admin@pycube.com').first()
    if admin is None:
        admin = User(email='admin@pycube.com')
        admin.set_password('admin')
        db.session.add(admin)
        db.session.commit()
        click.echo('Admin user created successfully.')
    else:
        click.echo('Admin user already exists.')

@click.command('reset-admin')
@with_appcontext
def reset_admin_command():
    """Reset the admin user password."""
    admin = User.query.filter_by(email='admin@pycube.com').first()
    if admin:
        admin.set_password('admin')
        db.session.commit()
        click.echo('Admin user password reset successfully.')
    else:
        click.echo('Admin user not found.')

@click.command('check-admin')
@with_appcontext
def check_admin_command():
    """Check if admin user exists and show details."""
    admin = User.query.filter_by(email='admin@pycube.com').first()
    if admin:
        click.echo(f'Admin user found:')
        click.echo(f'Email: {admin.email}')
        click.echo(f'ID: {admin.id}')
    else:
        click.echo('Admin user not found in database.') 