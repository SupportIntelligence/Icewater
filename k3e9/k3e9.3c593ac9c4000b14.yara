import "hash"

rule k3e9_3c593ac9c4000b14
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.3c593ac9c4000b14"
     cluster="k3e9.3c593ac9c4000b14"
     cluster_size="555 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="razy simbot backdoor"
     md5_hashes="['b51cd3ed4c4a0a9a636e80d4d3ea3e90', 'aa9ad6043570711dca602ce67c70d734', '96546722e82280f7f71727b406afc74e']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(5632,1536) == "b09e1f7c28fc22c6f6859d92fabdae15"
}

