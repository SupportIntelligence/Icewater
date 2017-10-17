import "hash"

rule m3e9_31b9e849c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.31b9e849c0000b32"
     cluster="m3e9.31b9e849c0000b32"
     cluster_size="248 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="swrort elzob zusy"
     md5_hashes="['cea2dd24d42dd1d3aba32c3012bdf215', '0552bc5dcde3790b15ad6c2ea056229b', 'ed8f92c0d974fe48741edc3453449d35']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(50176,1024) == "ccb05ba3663aace23ac2314559358c25"
}

