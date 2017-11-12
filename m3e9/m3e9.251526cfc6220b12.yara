import "hash"

rule m3e9_251526cfc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.251526cfc6220b12"
     cluster="m3e9.251526cfc6220b12"
     cluster_size="105301 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="vobfus zusy uouh"
     md5_hashes="['0077e54bb50d75ff991808d11bf018e4', '012a66aaadaa1327fde0a8f822964a90', '003b214958623ef278ec42cecf7661b9']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(119808,1024) == "7980f218ddc7e003b4787e4f217584a0"
}

