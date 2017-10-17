import "hash"

rule n3ed_591385a7ee208b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.591385a7ee208b32"
     cluster="n3ed.591385a7ee208b32"
     cluster_size="264 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['d3bae4d56464dd769d12bf123790e439', '3f564dfa51cd5ba95fcc177dfe7668d7', 'a8428ea09514c1dda92d3dd56c5a2d44']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(423936,1076) == "2464ede2d3405b3c500e9c2c3d78ec04"
}

