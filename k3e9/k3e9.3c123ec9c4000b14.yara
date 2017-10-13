import "hash"

rule k3e9_3c123ec9c4000b14
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.3c123ec9c4000b14"
     cluster="k3e9.3c123ec9c4000b14"
     cluster_size="60 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="razy simbot backdoor"
     md5_hashes="['c5bb1083a809a292be2c4a63f9c77a81', 'a3701af6c7162928838650b9eee5d283', '8da34502fd7bdf398665ff278cb596ae']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(5632,1536) == "b09e1f7c28fc22c6f6859d92fabdae15"
}

