import "hash"

rule k3e9_139da166cda39932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.139da166cda39932"
     cluster="k3e9.139da166cda39932"
     cluster_size="127 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['ad7f43c8b32f7e379edfe8818a0fe8f9', 'ca83cd83773476dab57ad57455665c40', '4aeff1b6e9cf1efa903d4ad1e52328b0']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(12288,1024) == "10942184959ee54e3c7f95e54fa08bca"
}

