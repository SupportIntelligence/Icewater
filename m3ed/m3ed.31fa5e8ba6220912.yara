import "hash"

rule m3ed_31fa5e8ba6220912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.31fa5e8ba6220912"
     cluster="m3ed.31fa5e8ba6220912"
     cluster_size="141 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="ramnit nimnul bmnup"
     md5_hashes="['6531a0c9c82a9d14bcb55e9e51b2d2e7', 'de3b7040d2f976f2845204955fa64a09', 'f64c2feebd907a88ee529465cafcd6fe']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(57344,1024) == "c36a39d15c14baf3463d80ea4a137d38"
}

