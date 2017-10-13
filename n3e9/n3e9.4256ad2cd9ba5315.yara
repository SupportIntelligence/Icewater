import "hash"

rule n3e9_4256ad2cd9ba5315
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.4256ad2cd9ba5315"
     cluster="n3e9.4256ad2cd9ba5315"
     cluster_size="5732 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['07057faf9b54c01290d0fa8d062fd594', '040177e045e3e6a1ee7d37d5aa38123e', '065c9b0a119d5f50cfa7cf47294c4d3b']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(712704,1024) == "6e9d1f71c4fc1d15075704839d17b462"
}

