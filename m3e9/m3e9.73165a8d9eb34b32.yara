import "hash"

rule m3e9_73165a8d9eb34b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.73165a8d9eb34b32"
     cluster="m3e9.73165a8d9eb34b32"
     cluster_size="353 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171018"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="swisyn bner mofksys"
     md5_hashes="['7d62b4ecec43a7eedf6544ba96e55d2a', 'b17ed4ae3f141caea6c271c4764010f3', 'b40637d33ca16bfc9ffe219af2dc6556']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 65536 and filesize < 262144
      and hash.md5(150528,1024) == "446877bb72cb1aac8e4408f2cd169793"
}

