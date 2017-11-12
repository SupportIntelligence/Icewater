import "hash"

rule o3ed_539c16cdc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3ed.539c16cdc6220b12"
     cluster="o3ed.539c16cdc6220b12"
     cluster_size="300 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['aba52b656ae373e5f4235118356baa93', '07d8f7d736cc476ef3311db4c99fca22', 'c67321e540b97a09c9ad495ca998b9db']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(1692672,1024) == "a8ac4510773e30cb008d5ba614f5bc6a"
}

