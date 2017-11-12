import "hash"

rule n3e9_3a1ebac1c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.3a1ebac1c4000b12"
     cluster="n3e9.3a1ebac1c4000b12"
     cluster_size="424 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171018"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="unruy backdoor banito"
     md5_hashes="['894d35e68f764b005f2bfa6193d771c6', '8ae94182ace383dd2645c1f4a396ad68', '29c702e056cf717aa6b162a4ca4c3c62']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 262144 and filesize < 1048576
      and hash.md5(324608,1024) == "5148818efca137413d3c7dbb35b47da9"
}

