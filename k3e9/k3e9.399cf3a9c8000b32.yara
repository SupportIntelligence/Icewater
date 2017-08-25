import "hash"

rule k3e9_399cf3a9c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.399cf3a9c8000b32"
     cluster="k3e9.399cf3a9c8000b32"
     cluster_size="17 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170815"
     license = "non-commercial use only"
     family="razy backdoor injector"
     md5_hashes="['5dc2f875e0bdcd8960606a5766ccc8d2', 'da440a1f2d762f81dce3478d9c2c3e0e', '8bd8284fea2dcd4e312004243be67e9e']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(24064,1536) == "42595f358d82ed008b0da3cc81ff353d"
}

