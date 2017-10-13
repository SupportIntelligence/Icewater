import "hash"

rule n3e9_16babac9cc000954
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.16babac9cc000954"
     cluster="n3e9.16babac9cc000954"
     cluster_size="537 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="allaple virut rahack"
     md5_hashes="['1287097d53ec5c55de6e01dc8bbee401', '69b1293150e7d4911ce2eb375b0346d0', 'a6b027e3fc7968a948854018dfc77f04']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(162784,1028) == "4f535038e929bf7b3ba8d207de4f234e"
}

