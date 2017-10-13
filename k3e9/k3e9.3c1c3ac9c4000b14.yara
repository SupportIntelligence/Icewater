import "hash"

rule k3e9_3c1c3ac9c4000b14
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.3c1c3ac9c4000b14"
     cluster="k3e9.3c1c3ac9c4000b14"
     cluster_size="576 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="razy simbot backdoor"
     md5_hashes="['adcf6216c8a40d28424d46ab8f383c8a', 'a49a76f86f7b16fe6de0e5b3dc0789d3', 'a288d5844470942465ce117ab529f9bf']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(5632,1536) == "b09e1f7c28fc22c6f6859d92fabdae15"
}

