import "hash"

rule k3e9_533ba3169e9f1916
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.533ba3169e9f1916"
     cluster="k3e9.533ba3169e9f1916"
     cluster_size="12 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob malicious"
     md5_hashes="['378b92134760df0f7927356c0b095ee9', 'c2767dbd084afbe43bc013d0d547ecd0', 'c2767dbd084afbe43bc013d0d547ecd0']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(12800,1280) == "9bec7913a2600fdf8cf39f32c8126b0b"
}

