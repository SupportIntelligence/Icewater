import "hash"

rule m3e9_611cb6c9cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.611cb6c9cc000b12"
     cluster="m3e9.611cb6c9cc000b12"
     cluster_size="704 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="allaple rahack backdoor"
     md5_hashes="['b2a458d1182f7c3d2585d780f4964719', 'b240b6eec081d205881e4e9c1ca8a6b5', '95994388a18d2e29979d96fc456cd97e']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(61952,1024) == "6a039dc6f36c112b920bef9b8a73cb0e"
}

