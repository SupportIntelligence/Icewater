import "hash"

rule k3e9_6bb1e438c0000912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6bb1e438c0000912"
     cluster="k3e9.6bb1e438c0000912"
     cluster_size="245 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="bxvp small trojanclicker"
     md5_hashes="['f0e4380f98d81836e479a5fbd2507af4', '98ee9aaf2a8e9185f5e8e625e3df1e23', '20513f5cd6295474708b3ef6647191bb']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(17408,1024) == "a745d823052c2c66c10967651d915e35"
}

