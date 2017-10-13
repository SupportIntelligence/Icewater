import "hash"

rule n3e9_31ca9099c2200932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.31ca9099c2200932"
     cluster="n3e9.31ca9099c2200932"
     cluster_size="82 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="zusy orbus siggen"
     md5_hashes="['06d471e2b42e65961f429b9b53edacb4', 'f8312703117d20b3095c1ee306e657ff', '0e6dd4cc7fefed7565f8dfa1c8c055b6']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(433152,1024) == "82a703004df5fdddd1924205610d269c"
}

