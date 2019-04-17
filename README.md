# P4I/O Prototype Software

This is the repository of the P4I/O prototype.

Please cite the original paper instead if you would like to cite this software:

> Mohammad Riftadi and Fernando A. Kuipers. 2019. P4I/O: Intent-Based Networking with P4. Proc. of 2019 2nd International Workshop on Emerging Trends in Softwarized Networks (ETSN 2019 at NetSoft). Paris, France.

or you can use the *bibtex* format:
```bibtex
@INPROCEEDINGS{Rift1906:P4IO,
    AUTHOR="Mohammad Riftadi and Fernando A. Kuipers",
    TITLE="{P4I/O:} {Intent-Based} Networking with {P4}",
    BOOKTITLE="2019 2nd International Workshop on Emerging Trends in Softwarized Networks
    (ETSN 2019 at NetSoft)",
    ADDRESS="Paris, France",
    DAYS=28,
    MONTH=jun,
    YEAR=2019
}
```

## Dependent Software Installation

The system was developed on Ubuntu 16.04 LTS, so please use it for optimum compatibility. Before you can run the prototype, you need to build and install the required software. Please use the script available in the `utils/` directory:

`sudo utils/bootstrap.sh`

The script should install all of the required dependencies. It was last tested on 17-Apr-2019 on a fresh installation of Ubuntu 16.04 LTS.

## Usage

You can run the software using the following command:
```bash
cd src
make

# you will get mininet console here..

# to stop mininet and clean the build dirs after exit
# mininet> exit

make clean
```

To change the intent while the virtual switch is running, you can run the `intent_listener.py` program:

```bash
cd src
sudo python intent_listener.py
```

From another session, you can then send an intent via a HTTP POST request with the data in the data.
For example (if you use `curl`):

```bash
curl -d "@intent.txt" -X POST http://localhost:5050/intent
```

Content example of `intent.txt`:

```
import drop_heavy_hitters

define intent dropHeavyHitters:
  to     any
  for    traffic('any')
  apply  drop_heavy_hitters
  with   threshold('more',50)

```

## Support

Support is not available for this software. If you have any question, you can open an issue in this repository or mail to m.riftadi@student.tudelft.nl. Please note that, however, an answer is not guaranteed.

## Credits

* Lead Developer: Mohammad Riftadi
* Mentor: Fernando Kuipers

## License

The MIT License (MIT)

Copyright (c) 2019 Mohammad Riftadi

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
