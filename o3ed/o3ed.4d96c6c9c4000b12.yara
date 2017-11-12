import "hash"

rule o3ed_4d96c6c9c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3ed.4d96c6c9c4000b12"
     cluster="o3ed.4d96c6c9c4000b12"
     cluster_size="5408 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['047d9d35fead790528355c0e7eee32ef', '39eea797787d62811ec1fc79c943f1d5', '4bd792ae62bafb3282963e0794a3c61c']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(1175552,1024) == "46afa767863a1b6f3ddb5d49841540cf"
}

