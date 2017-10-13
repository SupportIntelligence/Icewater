import "hash"

rule n3ed_5903c5a6dec31932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.5903c5a6dec31932"
     cluster="n3ed.5903c5a6dec31932"
     cluster_size="147 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="ramnit nimnul bmnup"
     md5_hashes="['a52a5c4f8fe5aff56e4ce6044bebe18f', '9a23616d5a636df2162c8f74d3f76d20', 'fdb024b176cec249f25952960b6c6de0']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(440662,1109) == "db48825dadc71a665893ba382ddae571"
}

