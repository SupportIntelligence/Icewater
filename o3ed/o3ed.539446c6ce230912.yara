import "hash"

rule o3ed_539446c6ce230912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3ed.539446c6ce230912"
     cluster="o3ed.539446c6ce230912"
     cluster_size="40 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['5bf24c4f03e840a1a934f01f8a9b0d2f', 'a79db8d3cce558d0df62436532055aa8', 'd7180d05f3df8f9662d6a560a3a31ec8']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(1622016,1024) == "bc25f198067512749893c52ddc9e5f7b"
}

