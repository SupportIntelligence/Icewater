import "hash"

rule k3e9_3c1a3ec9c4000b14
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.3c1a3ec9c4000b14"
     cluster="k3e9.3c1a3ec9c4000b14"
     cluster_size="436 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170815"
     license = "non-commercial use only"
     family="razy simbot backdoor"
     md5_hashes="['759c0b5bd8bf63a0ccf1f11687f99b03', '088eb2e3eae504ba5f9ccdce398f5080', 'abdb2018c929d38a6ad3070e73315e92']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(5632,1536) == "b09e1f7c28fc22c6f6859d92fabdae15"
}

