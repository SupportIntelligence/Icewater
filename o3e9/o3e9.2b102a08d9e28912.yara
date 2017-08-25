import "hash"

rule o3e9_2b102a08d9e28912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.2b102a08d9e28912"
     cluster="o3e9.2b102a08d9e28912"
     cluster_size="2425 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170815"
     license = "non-commercial use only"
     family="strictor noobyprotect advml"
     md5_hashes="['18e2754736bafb458c9260da5eb7194d', '0cbb5adcfdb4724d56fb2ceddc68de02', '0af37798698e4acd4b2bb65964950762']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(3104768,1024) == "b2044e2bd6dda24bdef1656ad5cf58c8"
}

