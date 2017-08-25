import "hash"

rule n3ed_4312dec1cc000b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.4312dec1cc000b16"
     cluster="n3ed.4312dec1cc000b16"
     cluster_size="136 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="ramnit nimnul bmnup"
     md5_hashes="['c3c2f73e8bac8d41bc81f779621055fb', '6278aeff02fe98f462e0bcb105ed4319', '578a7a0abe4ef9327e09e7d128266c19']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(144896,1024) == "a90ca570b58c7536d80c1fbeac643413"
}

