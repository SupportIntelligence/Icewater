import "hash"

rule k3e9_3c193ec9c4000b14
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.3c193ec9c4000b14"
     cluster="k3e9.3c193ec9c4000b14"
     cluster_size="570 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="razy simbot backdoor"
     md5_hashes="['7cdb57135f3704a2b8d0f982026d4b58', 'a621f3d929217178253c271ee2d4983f', 'b6b54fbd533508168c9085c3974be77c']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(5632,1536) == "b09e1f7c28fc22c6f6859d92fabdae15"
}

