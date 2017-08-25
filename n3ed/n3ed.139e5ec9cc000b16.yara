import "hash"

rule n3ed_139e5ec9cc000b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.139e5ec9cc000b16"
     cluster="n3ed.139e5ec9cc000b16"
     cluster_size="31 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="ramnit nimnul bmnup"
     md5_hashes="['d88a1b5eb3a226be6937649cab0126ed', 'aa46fe69788899eaac3125f34168d829', 'c8690a077abca1ae828c95dda29e517c']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(135168,1024) == "52cb6988b2f04ce844376970cd99da9e"
}

