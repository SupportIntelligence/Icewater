import "hash"

rule k3e9_1394a164cdc39932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.1394a164cdc39932"
     cluster="k3e9.1394a164cdc39932"
     cluster_size="14 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['d145a5927de747407df0083d7d3769b7', 'c726130a6a29c669863f26600b4776eb', 'c2a266e79e7347dca032406504705462']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(24576,1024) == "de88ae07cff08473a9c10f1d9aaff856"
}

