import "hash"

rule n3e9_6c18dbb8c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.6c18dbb8c8800b32"
     cluster="n3e9.6c18dbb8c8800b32"
     cluster_size="4482 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="bxqw ainslot shakblades"
     md5_hashes="['062d76121f0a945ad71bf7b4ad1c307e', '0ba48a463ac5e9103904e8f58e565905', '0fb2d8ee85205ea64adeec4adc0c3d8d']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(417792,1024) == "15572558512363aafa0609e94f90362e"
}

