# sslyze-parser
```sslyze-parser``` is used to parse the output of the populer tool [sslyze](https://github.com/nabla-c0d3/sslyze).
## Usage
You can provide the output of the given command to ```sslyze-parser```
```bash
sslyze --regular --targets_in=domain_list --json_out=output.json --heartbleed
```
This will create a csv file parsing the ```output.json```
```bash
python3 sslyze_parser.py -f output.json
```
## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.
## License
[MIT](https://choosealicense.com/licenses/mit/)
