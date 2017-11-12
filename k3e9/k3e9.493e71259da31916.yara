import "hash"

rule k3e9_493e71259da31916
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.493e71259da31916"
     cluster="k3e9.493e71259da31916"
     cluster_size="78 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['78ffc13fd7cf5394657e525eb915e1e9', '6b7ee097ed46f0e62cdced539e863748', '38331271e77eea5b7c0534e3488fa6ee']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(15872,1024) == "2be0f6e1890b843287e156fe1877e9d8"
}

