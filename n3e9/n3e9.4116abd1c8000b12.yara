import "hash"

rule n3e9_4116abd1c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.4116abd1c8000b12"
     cluster="n3e9.4116abd1c8000b12"
     cluster_size="298 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob madang"
     md5_hashes="['c5db898d2a12cc9b6d9c674f3f5970dd', 'a4aac49d759caf0129b2ea5898d28613', '551e6cbc3c9ba0b5401cad817d99d1ef']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(13312,1024) == "ece78b397ca093296952524f8300e1bc"
}

