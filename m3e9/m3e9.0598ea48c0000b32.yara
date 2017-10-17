import "hash"

rule m3e9_0598ea48c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.0598ea48c0000b32"
     cluster="m3e9.0598ea48c0000b32"
     cluster_size="6 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="aliser alisa small"
     md5_hashes="['18c37fb987ebb3fbc58bbb6c4db8dca8', '18c37fb987ebb3fbc58bbb6c4db8dca8', '00508c1c900937df800b38a6143a8e82']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(24829,1035) == "c6f77c628d2e6cfd7b633005aaadd062"
}

