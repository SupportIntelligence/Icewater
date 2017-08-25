import "hash"

rule k3e9_3c197ac9c4000b14
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.3c197ac9c4000b14"
     cluster="k3e9.3c197ac9c4000b14"
     cluster_size="206 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="razy simbot backdoor"
     md5_hashes="['cc49d3a8bd095cb5e908763799af9b8f', 'b9a6e85c16fdd592fc04c4363b0264dd', 'df2fe1360d7be8a2062b9dec5c760dcf']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(5632,1536) == "b09e1f7c28fc22c6f6859d92fabdae15"
}

