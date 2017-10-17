import "hash"

rule o3ed_4d96c2d9c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3ed.4d96c2d9c4000b12"
     cluster="o3ed.4d96c2d9c4000b12"
     cluster_size="67 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['be9394c91829790d71d1fd4f4678aca1', '5b5dc55fe67c9655474b942d6b6b5df9', 'c8ac9e699b1a9cd83a8ea06c58885c7b']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(1173504,1024) == "79a0ca033e9476bdf570bdd896445f12"
}

