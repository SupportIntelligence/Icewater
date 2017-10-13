import "hash"

rule m3e9_21b2144ad9bb1932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.21b2144ad9bb1932"
     cluster="m3e9.21b2144ad9bb1932"
     cluster_size="16 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="graftor backdoor delf"
     md5_hashes="['74447b69b592779790d4f17a3d3206b8', '0fe83ee3f534eeae2fe35c583b36a943', 'd68a75bb5683277c227b6637fb06b399']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(109897,1027) == "7e34e6c1ceb8efb2e8159562ded36072"
}

