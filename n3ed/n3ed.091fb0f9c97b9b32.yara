import "hash"

rule n3ed_091fb0f9c97b9b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.091fb0f9c97b9b32"
     cluster="n3ed.091fb0f9c97b9b32"
     cluster_size="27 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['cb5e2c7bf350f0e5b4964bf2d875d3a3', 'a32bf185cc165554d23fc7ce4e4b5dc1', 'a6d263fee070cb0f41f9c54ebd7fbbe3']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(596480,1024) == "144e96e91446d4ce95cb3c26d5e672a6"
}

