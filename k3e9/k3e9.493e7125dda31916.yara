import "hash"

rule k3e9_493e7125dda31916
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.493e7125dda31916"
     cluster="k3e9.493e7125dda31916"
     cluster_size="63 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['50f22844cfcb439c7348777b85e3aa4e', '6b1950d9888af3fc9f598d53b51d99d1', 'f397c4d779a04b837f6514c764f1cbbb']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(15872,1024) == "2be0f6e1890b843287e156fe1877e9d8"
}

