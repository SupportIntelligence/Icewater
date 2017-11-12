import "hash"

rule k3e9_139da164dcd39932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.139da164dcd39932"
     cluster="k3e9.139da164dcd39932"
     cluster_size="207 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['dce051db6eef455b22168798549c69cb', 'e741bb3bb2d1f4cdbc5ea573c5f5534b', 'd25972427416dddcb22935a7e5c98f2f']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(12288,1024) == "10942184959ee54e3c7f95e54fa08bca"
}

