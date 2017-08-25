import "hash"

rule k3e9_3c523ac9c4000b14
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.3c523ac9c4000b14"
     cluster="k3e9.3c523ac9c4000b14"
     cluster_size="61 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="backdoor razy simbot"
     md5_hashes="['bfd814c239bd3aeb609c881acf0f8bf4', 'a12458f3f8bc347d5b13989275aa7821', 'ce591e54a7ce9ee3b1cf6caa1acc9554']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(5632,1536) == "b09e1f7c28fc22c6f6859d92fabdae15"
}

