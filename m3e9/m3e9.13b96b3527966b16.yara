import "hash"

rule m3e9_13b96b3527966b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.13b96b3527966b16"
     cluster="m3e9.13b96b3527966b16"
     cluster_size="109 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="lethic gepys kryptik"
     md5_hashes="['b65928a9f4951eeaf1e6791778a29ce9', 'b828c7bbc19708e7de2a7d6ca072182e', 'b63ab2d70e7ca103637444764587e352']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(86528,1024) == "4aefef96e83f403d28be494bb8624f00"
}

