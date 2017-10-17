import "hash"

rule n3ed_5913c5a6dee31b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.5913c5a6dee31b32"
     cluster="n3ed.5913c5a6dee31b32"
     cluster_size="178 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['ab9ab524b3e196756e3dd2a3b01f344b', '041d44224a9503a7daf186f3780879d1', '65485b4e1368e150dd94db9031394594']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(418756,1036) == "210f6608b2efbfbe03110188284f4477"
}

