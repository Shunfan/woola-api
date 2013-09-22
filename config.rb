# General
Domain = "woo.la"
SSL = true

# Length
SlugLength = 3
MinUsernameLength = 3
MaxUsernameLength = 12
MinPasswordLength = 6
MaxPasswordLength = 18
SaltLength = 20
TokenLength = 40

# Case Sensitivity
SlugCaseSensitivity = true
UsernameCaseSensitivity = true

# Regular Expression
SlugRegExp = /^([a-zA-Z0-9-]{#{SlugLength}})$/
UrlRegExp = /^(https?:\/\/)?([\da-z\.-]+)\.([a-z\.]{2,6})([^*]*)\/?$/
SlugUrlRegExp = /^(http#{"s?" if SSL}:\/\/)?(woo.la)\/([a-z#{"A-Z" if SlugCaseSensitivity}0-9-]{#{SlugLength}})$/
EmailRegExp = /^([a-z0-9_\.-]+)@([\da-z\.-]+)\.([a-z\.]{2,6})$/
UsernameRegExp = /^[a-z#{"A-Z" if UsernameCaseSensitivity}0-9_-]{#{MinUsernameLength},#{MaxUsernameLength}}$/
PasswordRegExp = /^[\w\W]{#{MinPasswordLength},#{MaxPasswordLength}}$/

# Error message for validation
NotFoundMessage = "Not Found"
InvalidUsernameMessage = "Invalid username, the length of it should be #{MinUsernameLength}~#{MaxUsernameLength}"
InvalidEmailMessage = "Invalid email address"
InvalidPasswordMessage = "Invalid password, the length of it should be #{MinPasswordLength}~#{MaxPasswordLength}"
ExistUsernameMessage = "The username has been taken"
ExistEmailMessage = "The email address has been taken"
BadLoginMessage = "Bad login"
AccessDeniedMessage = "Access denied"
BlankParamsMessage = "Blank Parameters are provided"

# Other API
VirusTotalAPI = ""
WOTAPI = ""
