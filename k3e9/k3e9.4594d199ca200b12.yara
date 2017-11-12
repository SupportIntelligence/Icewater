import "hash"

rule k3e9_4594d199ca200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.4594d199ca200b12"
     cluster="k3e9.4594d199ca200b12"
     cluster_size="572"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171105"
     license = "RIL-1.0 [Rick's Internet License] "
     family="atraps banload coinbit"
     md5_hashes="['00405483993aee3362073947c92b8038','00af8753e881b95ca1d688081b17e7af','063fd56c624c197d4f6cd37e0053567a']"


   condition:
      
      filesize > 16384 and filesize < 65536
      and hash.md5(0,16384) == "c88f8b2a0240ea0868612072767f29c9"
}

