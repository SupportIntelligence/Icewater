import "hash"

rule n3ed_1b2fa91cdee31912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.1b2fa91cdee31912"
     cluster="n3ed.1b2fa91cdee31912"
     cluster_size="52 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170815"
     license = "non-commercial use only"
     family="ramnit nimnul bmnup"
     md5_hashes="['c8e771e68d5d235e50476560b115599f', '763642edda95d8f42bd830631b39d971', 'cbef7873379c324d9dcab7b9ad5fd800']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(290816,1024) == "f3e36befd0755f24ecffaff8a4db5c6e"
}

