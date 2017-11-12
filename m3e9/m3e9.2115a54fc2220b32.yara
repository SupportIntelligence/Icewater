import "hash"

rule m3e9_2115a54fc2220b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.2115a54fc2220b32"
     cluster="m3e9.2115a54fc2220b32"
     cluster_size="533 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="vobfus vbran autorun"
     md5_hashes="['b47bfad5814d4dedac19399412efe9ce', 'a84c3d548d965bcafa5235c91c0f2974', 'b7cfe0829c2510d6f076b4afd718130e']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(123904,1024) == "167709ba5441dbd5b814337c309ca8f4"
}

