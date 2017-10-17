import "hash"

rule m3e9_32a9549abea11932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.32a9549abea11932"
     cluster="m3e9.32a9549abea11932"
     cluster_size="13 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="gepys zbot trojandropper"
     md5_hashes="['094bfd0c6f57a58acd38fb929b186991', 'cd6eba274f0c5c8c8dd0a89c45472928', 'cd6eba274f0c5c8c8dd0a89c45472928']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(126690,1026) == "6d251cd0e6342bc1b2c179469345d311"
}

