import "hash"

rule k3e9_2b1ef3e9c8000b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.2b1ef3e9c8000b16"
     cluster="k3e9.2b1ef3e9c8000b16"
     cluster_size="227 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="razy backdoor simbot"
     md5_hashes="['0816a2c63ba4a4fe3cdc2f15bfff50ee', '814013ad73034d87a494743e785e6825', '061b65d9088b5a4a447ea4420cd530f1']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(25600,1536) == "b5ed7b029bc65184d8f3a398fb854e6d"
}

