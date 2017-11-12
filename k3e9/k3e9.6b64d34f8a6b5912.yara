import "hash"

rule k3e9_6b64d34f8a6b5912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64d34f8a6b5912"
     cluster="k3e9.6b64d34f8a6b5912"
     cluster_size="384 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171017"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob patched"
     md5_hashes="['ad44023057eaf5d5d4184ca5ff9fb64e', '21eea9df909c3a589c7e3700ea9b9eef', 'a975bebbc08e3585501ee8db51f44cbc']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536
      and hash.md5(3072,1036) == "a9d8654475cb556fb1cf62b83e2fa778"
}

