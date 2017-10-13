import "hash"

rule o3ed_539c16cdc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3ed.539c16cdc6220b12"
     cluster="o3ed.539c16cdc6220b12"
     cluster_size="188 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="ramnit nimnul bmnup"
     md5_hashes="['708213c3b2a82df911080a48f1468bcb', 'd7bdce6b6133a515e18244508220a9df', '9a2b52a30b48c65277f1e05cb6659968']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(1692672,1024) == "a8ac4510773e30cb008d5ba614f5bc6a"
}

