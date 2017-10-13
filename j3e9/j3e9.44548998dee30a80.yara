import "hash"

rule j3e9_44548998dee30a80
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=j3e9.44548998dee30a80"
     cluster="j3e9.44548998dee30a80"
     cluster_size="166 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="chir nimda runouce"
     md5_hashes="['b00d9b019407d623b149d0289af91c41', '7eb399b736d704aefed844119fd3c5f3', 'c546a4f63557ca18e4ebd784d6a558b5']"


   condition:
      filesize > 4096 and filesize < 16384
      and hash.md5(5266,1097) == "b1d6b9b43348eee21b43c6f2b7283037"
}

