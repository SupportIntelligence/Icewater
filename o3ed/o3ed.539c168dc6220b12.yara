import "hash"

rule o3ed_539c168dc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3ed.539c168dc6220b12"
     cluster="o3ed.539c168dc6220b12"
     cluster_size="369 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="ramnit nimnul bmnup"
     md5_hashes="['a8d9b9378f8457a0a0e91313a365dd92', '1f531f50f2b709be1ee6d57aba4c907f', 'aa05791fa8f368d5130657ead71ab9b1']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(1646592,1024) == "212ae30c5ded1d85044a3327f766f3a2"
}

