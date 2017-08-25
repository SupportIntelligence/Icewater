import "hash"

rule k3e9_3c553ac9c4000b14
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.3c553ac9c4000b14"
     cluster="k3e9.3c553ac9c4000b14"
     cluster_size="55 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="razy simbot backdoor"
     md5_hashes="['ef50e54e4b8b0daaa6bbf956ad236977', 'd89f01da7da3bf8baef2d8b448891aa4', 'cf07b932088ee784d1bb41ab4e0de833']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(5632,1536) == "b09e1f7c28fc22c6f6859d92fabdae15"
}

