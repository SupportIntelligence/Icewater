import "hash"

rule o3ed_131a9db9c5a90916
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3ed.131a9db9c5a90916"
     cluster="o3ed.131a9db9c5a90916"
     cluster_size="11 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['5ff5d0f500be9587dacc8c723bf0389d', 'a35576f9d2eb3f07bc5862e6ff585877', '5ff5d0f500be9587dacc8c723bf0389d']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(2137088,1024) == "ff5f1f7c34de76a2ed3703a11514ea4f"
}

