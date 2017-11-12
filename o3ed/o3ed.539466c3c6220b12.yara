import "hash"

rule o3ed_539466c3c6220b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3ed.539466c3c6220b12"
     cluster="o3ed.539466c3c6220b12"
     cluster_size="4637 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['07b26dcd638a3f5b81e7020c8d30bcfa', '50a1fb5bfb27945f51216b9a7aff20f4', '4578f2ef9674a90bd18c34d92049d794']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(1692672,1024) == "a8ac4510773e30cb008d5ba614f5bc6a"
}

