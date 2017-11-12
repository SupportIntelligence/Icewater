import "hash"

rule m3e9_619e3ac1cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.619e3ac1cc000b12"
     cluster="m3e9.619e3ac1cc000b12"
     cluster_size="764 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171018"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="allaple rahack backdoor"
     md5_hashes="['0d5c52ae3fc226219b548c32267218bb', '683d49c31e3aa5401aac80c929b9dda3', 'a0f19319d40bdb8297f9137c704dcbae']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 65536 and filesize < 262144
      and hash.md5(62976,1024) == "38345c2f0e0fb848e12408e6736482bc"
}

