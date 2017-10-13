import "hash"

rule n3e9_31ca1099c2200932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.31ca1099c2200932"
     cluster="n3e9.31ca1099c2200932"
     cluster_size="3 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170815"
     license = "non-commercial use only"
     family="zusy orbus siggen"
     md5_hashes="['42af40c46527c057648ed2d74b7062ce', 'a7fa21f980e54b66c21d5f4c57765b61', '42af40c46527c057648ed2d74b7062ce']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(446464,1024) == "7115d185c1213a6d0abcd06089003f2c"
}

