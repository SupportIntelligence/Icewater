import "hash"

rule k3e9_493e730595a31916
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.493e730595a31916"
     cluster="k3e9.493e730595a31916"
     cluster_size="10 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['6a46deacffa385e54746db5c4d0df09a', '9c451b347293e145f8bd60e38257194b', '7912a5694a2f61e958bd7a2a7bc36e61']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(15872,1024) == "2be0f6e1890b843287e156fe1877e9d8"
}

