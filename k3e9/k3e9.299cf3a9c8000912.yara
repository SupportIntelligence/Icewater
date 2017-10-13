import "hash"

rule k3e9_299cf3a9c8000912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.299cf3a9c8000912"
     cluster="k3e9.299cf3a9c8000912"
     cluster_size="22 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="backdoor razy injector"
     md5_hashes="['bb6a594f3979f96644d524b59d3c7fbf', 'b1495e46de40376bd61858a63f834a15', 'a5fa15ae033ffe2976d114fdccd7bac5']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(24064,1536) == "42595f358d82ed008b0da3cc81ff353d"
}

