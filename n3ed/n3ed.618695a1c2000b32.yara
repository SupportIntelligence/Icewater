import "hash"

rule n3ed_618695a1c2000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.618695a1c2000b32"
     cluster="n3ed.618695a1c2000b32"
     cluster_size="29 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['75cd03743a018dbbb67ed9a613df68cc', '19b77d3d49ef7a2b997aaa517598d01c', 'da10f2b3061cdae408cea0484f6ee955']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(156672,1536) == "0f4c07f5fc878e2aa1805fefc0c25f7a"
}

