import "hash"

rule n3ed_0ca3390f1a127936
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.0ca3390f1a127936"
     cluster="n3ed.0ca3390f1a127936"
     cluster_size="5746 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="ramnit nimnul bmnup"
     md5_hashes="['0f76d5aa1b2041305fe9b3854e7ad8b7', '037ecba3777b3d1b7f585d68e3a04cb2', '1ca3933240656580c01f0447f5395032']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(641536,1536) == "b83d54d068c17ef67e7b9236dbb3528c"
}

