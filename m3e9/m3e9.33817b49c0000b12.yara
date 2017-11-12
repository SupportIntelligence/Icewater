import "hash"

rule m3e9_33817b49c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.33817b49c0000b12"
     cluster="m3e9.33817b49c0000b12"
     cluster_size="530 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171017"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ibryte installer optimum"
     md5_hashes="['268d8db7525e251e3e2b669858b2a3d9', '39ab3258f95653293d51bcdd35a50304', '832819f0e427fcab1a4e90d8e6d8ac71']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 65536 and filesize < 262144
      and hash.md5(50239,1045) == "1566f3b1e6b392168e0c4962aa6b8ed9"
}

