import "hash"

rule m3ed_521c03b919464d56
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.521c03b919464d56"
     cluster="m3ed.521c03b919464d56"
     cluster_size="19 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="ramnit nimnul bmnup"
     md5_hashes="['a6904693913b9f2f2ffc3ce604789d3d', 'be101a5d3fcd782dc467998a8aea8495', 'd0bfe10d71c3b9b6ad1c161d2d38049a']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(135168,1024) == "52cb6988b2f04ce844376970cd99da9e"
}

