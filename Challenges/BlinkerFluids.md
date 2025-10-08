This is a web challenge with web app made of node and express js as backend.We can create a invoice using this app which provide the data in markdown format and then the web server process the data and create a pdf on it.

The backend uses a md-to-pdf which is a aexternal library which have a code execution vulnerability.

 

```bash
const express        = require('express');
const router         = express.Router();
const MDHelper       = require('../helpers/MDHelper.js');

<SNIP>

router.post('/api/invoice/add', async (req, res) => {
    const { markdown_content } = req.body;

    if (markdown_content) {
        return MDHelper.makePDF(markdown_content)
            .then(id => {
                db.addInvoice(id)
					.then(() => {
						res.send(response('Invoice saved successfully!'));
					})
					.catch(e => {
						res.send(response('Something went wrong!'));
					})
            })
            .catch(e => {
                console.log(e);
                return res.status(500).send(response('Something went wrong!'));
            })
    }
    return res.status(401).send(response('Missing required parameters!'));
});
```

```bash
const { mdToPdf }    = require('md-to-pdf')
const { v4: uuidv4 } = require('uuid')

const makePDF = async (markdown) => {
    return new Promise(async (resolve, reject) => {
        id = uuidv4();
        try {
            await mdToPdf(
                { content: markdown },
                {
                    dest: `static/invoices/${id}.pdf`,
                    launch_options: { args: ['--no-sandbox', '--js-flags=--noexpose_wasm,--jitless'] } 
                }
            );
            resolve(id);
        } catch (e) {
            reject(e);
        }
    });
}
```

We can see it uses the mdtopdf library to convert the md to pdf

https://security.snyk.io/vuln/SNYK-JS-MDTOPDF-1657880

We can read about it more on snyk page, we can copy the payload we will send through the request and get code execution.

For this challenge i will read the flag and send a curl request to my webhook including the flag in it.

<img width="1152" height="497" alt="image" src="https://github.com/user-attachments/assets/f257644f-4a2b-4f75-8509-169b52910f05" />


<img width="1212" height="394" alt="image" src="https://github.com/user-attachments/assets/d87e80a5-c718-4069-886b-53a056a1d385" />
