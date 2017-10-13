import "hash"

rule k3e9_0b1ef3a9c8000932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.0b1ef3a9c8000932"
     cluster="k3e9.0b1ef3a9c8000932"
     cluster_size="15 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="razy backdoor injector"
     md5_hashes="['a03d104226789f4a630df93b772ddbc8', 'c80517ee49c0ed2e0f50dc9e76bb4357', 'd84520e076ad673c716b5dbc20f23420']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(24064,1536) == "42595f358d82ed008b0da3cc81ff353d"
}

