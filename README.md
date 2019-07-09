# WPDevOps
Run useful development operations in the browser javascript console with wpdevtools(). Run wpdevtools() for usage information.

## Usage
jsdevtools(params)

## Params (object)
| key | value | method |
| --- | --- | --- |
| git | config, pull or status | POST | 
| repo | theme or plugin path relative to wp-content/ | POST |
| branch | branch name | POST |
| login | username:password | POST |
| cmd | terminal command | POST |
| upload | upload file | FILE |

## Example
`
devops({
    git:'pull',
    repo:'plugins/wp-devops',
    branch:'master' 
})
`
