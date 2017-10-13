import "hash"

rule n3ed_31a4468d86221132
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.31a4468d86221132"
     cluster="n3ed.31a4468d86221132"
     cluster_size="111 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="ramnit nimnul bmnup"
     md5_hashes="['fc7c5f6ebbf7090d5b37c3d14ba565ae', '188ed9aedffd4781184dd6b7d0557df2', 'e61bf1d2bb383217e280e7f42b9b1417']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(286720,1024) == "21cd1f5dd6f252371e6aa6e53f74b815"
}

