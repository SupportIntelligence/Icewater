import "hash"

rule m3e9_5c1ab44bc6220b22
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.5c1ab44bc6220b22"
     cluster="m3e9.5c1ab44bc6220b22"
     cluster_size="6 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="zusy backdoor androm"
     md5_hashes="['165c69d140eadabed0cf389ab0b640c7', '165c69d140eadabed0cf389ab0b640c7', 'a2dfe3a6e208e0f9680a5a8f908b9d7b']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(24576,1024) == "0dfc0e71a745ccacf205794e88ed4ec7"
}

