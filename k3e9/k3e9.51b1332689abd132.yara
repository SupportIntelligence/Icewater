import "hash"

rule k3e9_51b1332689abd132
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.51b1332689abd132"
     cluster="k3e9.51b1332689abd132"
     cluster_size="4 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['c96db997162a7ca68be98cda1e2b1b77', 'c96db997162a7ca68be98cda1e2b1b77', 'c96db997162a7ca68be98cda1e2b1b77']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(5120,1024) == "5ab8258470efa3d600fcbe17d59a8cd4"
}

