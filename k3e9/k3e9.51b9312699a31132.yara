import "hash"

rule k3e9_51b9312699a31132
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.51b9312699a31132"
     cluster="k3e9.51b9312699a31132"
     cluster_size="5 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['c2c2adacdd8294eb75a36fcf7db18c58', 'c2c2adacdd8294eb75a36fcf7db18c58', 'c4baf5ba395c7a2734a20afc0b676c4a']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(5120,1024) == "5ab8258470efa3d600fcbe17d59a8cd4"
}

