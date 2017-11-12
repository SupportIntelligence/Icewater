import "hash"

rule m3e9_16c1b9494a9664f2
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.16c1b9494a9664f2"
     cluster="m3e9.16c1b9494a9664f2"
     cluster_size="189 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="shipup razy zbot"
     md5_hashes="['bc617e9a517a284dc11f54cbbcac47e3', 'bf8777247dc2aff17a58918d063aaab0', 'b7bd7b813bca07c1db206001db78a265']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(235520,1024) == "e5c64c011f9df09a712f0d7b8c3391f6"
}

