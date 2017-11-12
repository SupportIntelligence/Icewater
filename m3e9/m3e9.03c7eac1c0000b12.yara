import "hash"

rule m3e9_03c7eac1c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.03c7eac1c0000b12"
     cluster="m3e9.03c7eac1c0000b12"
     cluster_size="1101 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="upatre ipatre kryptik"
     md5_hashes="['2ea5c5541eea3edce17b541c1bd13819', '3fcffb80d0269f924ff052be0914fdf1', '9f764a7281f00a1a227d1b4ebea94fe4']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(15360,1024) == "514cef5a384befc1c812053c3885a0b8"
}

