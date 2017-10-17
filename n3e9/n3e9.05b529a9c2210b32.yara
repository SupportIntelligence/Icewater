import "hash"

rule n3e9_05b529a9c2210b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.05b529a9c2210b32"
     cluster="n3e9.05b529a9c2210b32"
     cluster_size="912 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="renamer delf grenam"
     md5_hashes="['5435ad152baefc0564b64eb92dc56752', 'e12622b644667aa8633d592808a49da1', '6eaa4d2abc96698ee5065e02a02ea9f0']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(463929,1081) == "87a736d096dd8f6c5aae9a67e116e67e"
}

