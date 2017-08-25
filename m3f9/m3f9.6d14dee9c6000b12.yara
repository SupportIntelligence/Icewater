import "hash"

rule m3f9_6d14dee9c6000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f9.6d14dee9c6000b12"
     cluster="m3f9.6d14dee9c6000b12"
     cluster_size="701 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="symmi swisyn abzf"
     md5_hashes="['95a15ce15e759e07a27a1fdd1015a286', '9875c895b1f1a03568b4097a64673c56', '199f8b4777284666d65cb1dd4ff70b51']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(8192,1024) == "9f712feaffef3b90b4425924542b4546"
}

