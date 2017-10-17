import "hash"

rule m3e9_2129213c80801132
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.2129213c80801132"
     cluster="m3e9.2129213c80801132"
     cluster_size="868 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob shodi"
     md5_hashes="['a9a54e14acb7c83c2425479526cb15f4', '02371a7e2617d1b070ce6ad0fa0a0ecb', 'a1ec8e10b6772656d8dd2d5cbe9d204e']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(104960,1024) == "dcaade34268af7cbd90bb99f9294d68b"
}

