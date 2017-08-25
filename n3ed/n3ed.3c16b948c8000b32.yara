import "hash"

rule n3ed_3c16b948c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.3c16b948c8000b32"
     cluster="n3ed.3c16b948c8000b32"
     cluster_size="235 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170815"
     license = "non-commercial use only"
     family="attribute heuristic highconfidence"
     md5_hashes="['79c293c61b16fec0ffa1c6c71a23b014', '397c30a129ff23fa40c2eda36ab46a0e', '889da84086a8a58d5405d965aaf36896']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(240128,1024) == "847260ec25d49010b15515a5b48e567d"
}

