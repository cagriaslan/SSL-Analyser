# SSL-Analyser
```SSL-Analyser``` is used to analyse SSL certificates and vulnerabilities. It depends on the populer tool [sslyze](https://github.com/nabla-c0d3/sslyze).
## Usage
You can provide the output of the given command to ```sslyze-parser```
```bash
python3 sslyze_parser.py -f input_file -o output_file
```
This will create a csv file ```output_file.json``` including detailed information with the given domain(s). Input file should be a txt file containing domain, IP pairs.
## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.
