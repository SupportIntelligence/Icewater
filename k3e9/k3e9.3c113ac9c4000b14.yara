import "hash"

rule k3e9_3c113ac9c4000b14
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.3c113ac9c4000b14"
     cluster="k3e9.3c113ac9c4000b14"
     cluster_size="267 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="razy simbot backdoor"
     md5_hashes="['ade5f96c1f621f1203a6adaffe4da0cd', 'b1ecac8dcc7c0696b4fa8ae9f1e01279', 'c70b027bca01a89151b90163743eb1f2']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(6400,256) == "1371fd7f3206a21874fbe56ff62fb073"
}

