import "hash"

rule k3e9_3c1b3ac9c8000b14
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.3c1b3ac9c8000b14"
     cluster="k3e9.3c1b3ac9c8000b14"
     cluster_size="301 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="razy simbot backdoor"
     md5_hashes="['bb3eeb4361313f039770bc295c9066f7', 'c96b848dde4bfd7a682301c1c9b65721', 'a16c93d8cf14c793d36c5ca47dd255f3']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(5632,1536) == "b09e1f7c28fc22c6f6859d92fabdae15"
}

