import "hash"

rule m3e9_32cb2315486b48ba
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.32cb2315486b48ba"
     cluster="m3e9.32cb2315486b48ba"
     cluster_size="88 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="shipup kazy kryptik"
     md5_hashes="['bca3bc35b61781106a87e980a2545c92', 'd736c24b37f7e136bdc46db9f21e4c41', 'a130e99313cd9594e9f201c809dddd6f']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(238592,1024) == "e5c64c011f9df09a712f0d7b8c3391f6"
}

