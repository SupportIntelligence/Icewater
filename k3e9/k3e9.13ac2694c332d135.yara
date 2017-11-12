import "hash"

rule k3e9_13ac2694c332d135
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.13ac2694c332d135"
     cluster="k3e9.13ac2694c332d135"
     cluster_size="3 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="qukart berbew backdoor"
     md5_hashes="['bb0755c4125f8eb96b778ddc5e01c9b9', 'a49a792ea6058d467429f0855a3ebade', 'a49a792ea6058d467429f0855a3ebade']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(49603,1249) == "d06857e133fd37b7cc5535176ea36368"
}

