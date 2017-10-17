import "hash"

rule m3e9_32cb2534486b48ba
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.32cb2534486b48ba"
     cluster="m3e9.32cb2534486b48ba"
     cluster_size="135 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="shipup kazy kryptik"
     md5_hashes="['cdbf6d572a9683510c24f4e9a4180863', '205577988fc9df81351927e1689d1256', 'c065d852f0526927374eb42551c46f10']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(238592,1024) == "e5c64c011f9df09a712f0d7b8c3391f6"
}

