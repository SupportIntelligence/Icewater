import "hash"

rule k3e9_3c173ac9c4000b14
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.3c173ac9c4000b14"
     cluster="k3e9.3c173ac9c4000b14"
     cluster_size="91 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170815"
     license = "non-commercial use only"
     family="razy simbot backdoor"
     md5_hashes="['a3327ed2a2b5e8b0d77454ce6711a721', 'a68a624f7f4dd0983ceeb32a3420b6eb', '63e7c52206c4ace92944126c9b2adfb5']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(5632,1536) == "b09e1f7c28fc22c6f6859d92fabdae15"
}

