import "hash"

rule k3e9_2f94e438c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.2f94e438c0000b32"
     cluster="k3e9.2f94e438c0000b32"
     cluster_size="472 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="bxvp small trojanclicker"
     md5_hashes="['0c5af72eeac735060ac16fd69bc1efa2', '90f8208a201fb0f0a66eea3ef84f7d84', 'b297e510998a5b8686e8881d349a3515']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(17408,1024) == "a745d823052c2c66c10967651d915e35"
}

