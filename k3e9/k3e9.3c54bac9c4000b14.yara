import "hash"

rule k3e9_3c54bac9c4000b14
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.3c54bac9c4000b14"
     cluster="k3e9.3c54bac9c4000b14"
     cluster_size="4 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="razy simbot backdoor"
     md5_hashes="['c20ced70469f1d733e2f7b45a8ba4c1a', '2a4b04588ccb045ac87a5a7e581c45ca', 'c20ced70469f1d733e2f7b45a8ba4c1a']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(5632,1536) == "b09e1f7c28fc22c6f6859d92fabdae15"
}

