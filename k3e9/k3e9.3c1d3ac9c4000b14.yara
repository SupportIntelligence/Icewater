import "hash"

rule k3e9_3c1d3ac9c4000b14
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.3c1d3ac9c4000b14"
     cluster="k3e9.3c1d3ac9c4000b14"
     cluster_size="1167 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="razy simbot backdoor"
     md5_hashes="['a3b88a517ab01b7c73985bd6a4c2c2de', '3292e897855b988fe3b304d422b9e89b', '3fedd62d54bc69437a1ce1dae9d9feca']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(5632,1536) == "b09e1f7c28fc22c6f6859d92fabdae15"
}

