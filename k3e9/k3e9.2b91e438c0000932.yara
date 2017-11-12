import "hash"

rule k3e9_2b91e438c0000932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.2b91e438c0000932"
     cluster="k3e9.2b91e438c0000932"
     cluster_size="146 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="bxvp small trojanclicker"
     md5_hashes="['dc8c407c29f48d0d360bd3ed9c14cc0a', '6d7de384a444e686719b5e7320a8b226', 'b7af33fe169e9bce4817ffe18b5b86af']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(17408,1024) == "a745d823052c2c66c10967651d915e35"
}

