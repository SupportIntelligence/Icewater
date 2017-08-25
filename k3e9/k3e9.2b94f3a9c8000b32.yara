import "hash"

rule k3e9_2b94f3a9c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.2b94f3a9c8000b32"
     cluster="k3e9.2b94f3a9c8000b32"
     cluster_size="42 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="backdoor razy injector"
     md5_hashes="['c49f89b2ecdfe5df161ec67afb9c2313', 'a58ffca86b5da62f55e765579e36e8ac', 'cc5ce37cb0a5df9c9ff83920880f2060']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(24064,1536) == "42595f358d82ed008b0da3cc81ff353d"
}

