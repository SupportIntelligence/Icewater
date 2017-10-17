import "hash"

rule n3e9_258e1729c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.258e1729c8800b32"
     cluster="n3e9.258e1729c8800b32"
     cluster_size="188 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="vobfus sirefef jorik"
     md5_hashes="['31b6ac3a76d446a5fd62a6492a3231ef', '70841a1429f7d3070f261e63d3b8aa26', 'f623cb4acd6d5e9b951b18d5291d929f']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(395008,1024) == "265d3a6bd81f0b9a9b409e665ea3f6aa"
}

