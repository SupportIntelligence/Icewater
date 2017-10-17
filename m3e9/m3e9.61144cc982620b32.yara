import "hash"

rule m3e9_61144cc982620b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.61144cc982620b32"
     cluster="m3e9.61144cc982620b32"
     cluster_size="96 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="vobfus sirefef jorik"
     md5_hashes="['89196fc690699f28f042d31f1abed677', 'c614ad8f09430979d1fc03076fa9d255', '2d9d617c76414687ee88741ab9526468']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(126976,1024) == "f5c7debbf838ae6831170bd3da12dbe7"
}

