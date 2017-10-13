import "hash"

rule o3e9_019a9b99c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.019a9b99c2200b12"
     cluster="o3e9.019a9b99c2200b12"
     cluster_size="112 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="vbkrypt eyestye injector"
     md5_hashes="['b6cac7cdae90b9aa379eaf684dd68e4b', '0e004cf2a9630198befbfc4fb85bf553', '0b4591bfe5761dd92307b189fd873903']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(1822720,1024) == "80c01834b7d4bf3e3cac832610085fb1"
}

