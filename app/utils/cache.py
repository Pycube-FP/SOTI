from flask_caching import Cache

# Initialize cache with default config
cache = Cache(config={
    'CACHE_TYPE': 'simple',  # Use simple cache for development
    'CACHE_DEFAULT_TIMEOUT': 300  # Default timeout of 5 minutes
})

def init_cache(app):
    """
    Initialize the cache with the application instance.
    """
    # Update cache config from app config if available
    if app.config.get('CACHE_TYPE'):
        cache.config.update(app.config)
    
    cache.init_app(app) 