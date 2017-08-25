import "hash"

rule n3ed_7c16b948c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.7c16b948c8000b32"
     cluster="n3ed.7c16b948c8000b32"
     cluster_size="141 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170815"
     license = "non-commercial use only"
     family="attribute heuristic highconfidence"
     md5_hashes="['65cb3d02ce1b849edb8a51202f236835', 'cadff364261ab871db3f39f3b63bb5bd', '9b75887e8c83a74fa732897260f1f4ce']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(299163,1075) == "0eb50467ae7d70fe13e8d422bd72ce67"
}

