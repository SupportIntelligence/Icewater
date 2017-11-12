import "hash"

rule n3ed_591385a396d30b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.591385a396d30b32"
     cluster="n3ed.591385a396d30b32"
     cluster_size="65 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['bfdd926da996f4b07c47e0c510a27e56', '1e81b73d252726b7b2f308887b3dcc26', 'cd6fae78edb4d9500dce0e0786b6c2bf']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(418756,1036) == "210f6608b2efbfbe03110188284f4477"
}

