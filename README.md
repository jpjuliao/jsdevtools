# WPDevOps
Run useful development operations. 

## Javascript Usage
This plugin registers the javascript function: devops(). Run devops() for usage information.

### Params (object)
| key | value | method |
| --- | --- | --- |
| git | config, pull or status | POST | 
| repo | theme or plugin path relative to wp-content/ | POST |
| branch | branch name | POST |
| login | username:password | POST |
| cmd | terminal command | POST |
| upload | upload file | FILE |

### Example
`
devops({
    git:'pull',
    repo:'plugins/wp-devops',
    branch:'master' 
})
`
