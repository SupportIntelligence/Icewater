import "hash"

rule k3e9_3c1b3ec9c4000b14
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.3c1b3ec9c4000b14"
     cluster="k3e9.3c1b3ec9c4000b14"
     cluster_size="268 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="razy simbot backdoor"
     md5_hashes="['c42c3efa4721927365d2d0870c10010b', '6cd52f63e9aa92e9b093fb4ddcd937ee', 'a0510c1886f76c3bcf4796bdb89aaed5']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(5632,1536) == "b09e1f7c28fc22c6f6859d92fabdae15"
}

