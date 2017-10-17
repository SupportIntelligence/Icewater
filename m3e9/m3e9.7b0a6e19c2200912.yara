import "hash"

rule m3e9_7b0a6e19c2200912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.7b0a6e19c2200912"
     cluster="m3e9.7b0a6e19c2200912"
     cluster_size="238 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="vobfus sirefef vbkrypt"
     md5_hashes="['c5d9adcac7a1c8f7ffe38416e191fdf1', 'e3ae4bb03654756fed58890a838d9f4d', '8f0d522b50a722c06fe7afed104161e0']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(83968,1024) == "f6112acd75337af116fd4e5d51f4ef93"
}

