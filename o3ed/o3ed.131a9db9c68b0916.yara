import "hash"

rule o3ed_131a9db9c68b0916
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3ed.131a9db9c68b0916"
     cluster="o3ed.131a9db9c68b0916"
     cluster_size="204 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['c2ea67d086f2f3bb8f926a0ece94d116', 'c4e2ec1a821a5d15db0c91911f23060c', 'cdba6b94115dda1ebd86c5eb4ca7a27c']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(2137088,1024) == "ff5f1f7c34de76a2ed3703a11514ea4f"
}

