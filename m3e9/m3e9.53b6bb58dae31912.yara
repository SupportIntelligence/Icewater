import "hash"

rule m3e9_53b6bb58dae31912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.53b6bb58dae31912"
     cluster="m3e9.53b6bb58dae31912"
     cluster_size="480 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170815"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['b1314ad41ae893a05c9b9ff718ed93d5', 'a27a231f6bbf1bbf9c2b15664709b8c1', '39c8e131c0035f6bbece4ba025c3067a']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(80896,1280) == "c23266a7380bf3daa3a8422c6d2fd0c8"
}

