import "hash"

rule k3e9_15e10a969ee311b2
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.15e10a969ee311b2"
     cluster="k3e9.15e10a969ee311b2"
     cluster_size="39 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['afe835b59058fcfdf3b31f809a4e38c3', '73d4526eb8824def69a4dca05cb6713d', 'd4a20f9b77adf9afa5d41ebe1333880f']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(8448,256) == "1e62b5fcfb3e134c6d1424488c1d6c5d"
}

