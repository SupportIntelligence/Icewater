import "hash"

rule k3e9_4b9b16e9c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.4b9b16e9c8800b32"
     cluster="k3e9.4b9b16e9c8800b32"
     cluster_size="8091 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="bavs trojandownloader upatre"
     md5_hashes="['11ac7fcb0194493a6a0119560d151f49', '0778f42dcd455d8cc4b1b80e0c3262f6', '0b00968e829979a64662b52a8a981ad8']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(16054,1054) == "c6c893a0229a295473f1d2e717196e00"
}

