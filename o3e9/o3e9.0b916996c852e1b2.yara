import "hash"

rule o3e9_0b916996c852e1b2
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.0b916996c852e1b2"
     cluster="o3e9.0b916996c852e1b2"
     cluster_size="345 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="installmonster malicious filerepmalware"
     md5_hashes="['c48be22c944ffd6975f39530f514719d', 'de0084ad9b6ea9811ff6148b3c2500bc', 'd36226da0fe8295fff4998cd5c28d705']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(2271232,1024) == "c0d865515e773c9b3073b0c7299db46c"
}

