import "hash"

rule o3ed_7d4c2949c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3ed.7d4c2949c0000b32"
     cluster="o3ed.7d4c2949c0000b32"
     cluster_size="5 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul malicious"
     md5_hashes="['a282b9551c14e6306a2d0836aad30f45', '12d9d6c4f8f19ada8bacdf084454d58b', '091c32f14a0e8e243ee063eb4ab5d326']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(641536,1536) == "b83d54d068c17ef67e7b9236dbb3528c"
}

