# AuthToken 
Simple `Authentication Token Manager` System.

## Installation

just include `AuthToken.php` into your document.

```php
include_once "AuthToken.php";
```

## Usage
Generate Token:
- you can pass the username to this method (`optional`)
- If you have already created a session called `username`, the `username` will be set automatically and does not need to be set separately.
```php
AuthToken::generate();
```
Check Token:
- You must use a username if you used it to Generate a token.
- this method returns `true` or `false`
```php
AuthToken::check();
```
Delete Token:
```php
AuthToken::delete();
```