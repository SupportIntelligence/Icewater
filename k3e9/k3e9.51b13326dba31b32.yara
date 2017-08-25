import "hash"

rule k3e9_51b13326dba31b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.51b13326dba31b32"
     cluster="k3e9.51b13326dba31b32"
     cluster_size="6 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['9b9bd1b9b239405695ca59ef8431b54c', 'bb1bda1bb9e9d45f4f6bbd6fa98f9e3d', 'bb1bda1bb9e9d45f4f6bbd6fa98f9e3d']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(4096,1024) == "cf87fde8b009ce16dbc49360714f6a2f"
}

