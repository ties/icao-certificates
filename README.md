# ICAO master list

After a discussion on [Twitter](https://twitter.com/BWBroersma/status/1403276132678504452)
it turns out there were very few examples of how to parse the ICAO Master List.
This repository attempts to capture some of this information.

You can download the ICAO master list from [2] or using the curl command from
[0].

The ICAO Master List is a CMS signed object (see [1, pg.25]),
in the `eContent` there is a `SET` of `Certificate` entries.

Exploring the ICAO Public Key Directory (PKD) [3] is left as future work.


[0]: https://gist.githubusercontent.com/bwbroersma/6e06561ffe99b311c0608e5b8cd39e3d/raw/775e8cb271a598b5332a66e727448d9d26bfaf7a/ICAOMasterList.sh

[1]: https://www.icao.int/publications/Documents/9303_p12_cons_en.pdf
[2]: https://www.icao.int/Security/FAL/PKD/Pages/icao-master-list.aspx
[3]: https://download.pkd.icao.int/


```
$ node src/masterList.mjs
...
output, writes SET of Certificate to certificates.bin
...
$ dumpasn1 certificates.bin
