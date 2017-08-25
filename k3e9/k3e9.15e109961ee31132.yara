import "hash"

rule k3e9_15e109961ee31132
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.15e109961ee31132"
     cluster="k3e9.15e109961ee31132"
     cluster_size="57 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['cfec1ecc0501c67dada590318db1a376', 'cf134720fdbfe2e80c166dd7e09b5d7f', 'b3ec8f571e06f4ee53043c2c91178354']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(16384,1024) == "479d8ddd4ba5d72b0f7fc8167a804cd4"
}

