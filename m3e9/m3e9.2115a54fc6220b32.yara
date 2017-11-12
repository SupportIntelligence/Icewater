import "hash"

rule m3e9_2115a54fc6220b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.2115a54fc6220b32"
     cluster="m3e9.2115a54fc6220b32"
     cluster_size="709 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="vobfus vbran vbna"
     md5_hashes="['b13462377f67c49e55d7017fec78013d', 'b054e401cebfbba09ce7ef9a3b12e0d6', 'a6379bb243c550446c03c9933eba9029']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(123904,1024) == "7980f218ddc7e003b4787e4f217584a0"
}

