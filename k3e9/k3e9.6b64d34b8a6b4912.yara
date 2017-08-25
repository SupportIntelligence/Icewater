import "hash"

rule k3e9_6b64d34b8a6b4912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64d34b8a6b4912"
     cluster="k3e9.6b64d34b8a6b4912"
     cluster_size="74 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170815"
     license = "non-commercial use only"
     family="virut virtob patched"
     md5_hashes="['c9f2c0aade1f695171602c82adfcdea6', 'cd99274d35752fa45c3596317da29598', 'c750cf596b31fda0aa5f79b46c412e75']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(14468,1036) == "3fc9b6513c182f90d41c33f933010485"
}

