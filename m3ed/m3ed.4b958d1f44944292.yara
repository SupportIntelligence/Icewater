import "hash"

rule m3ed_4b958d1f44944292
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.4b958d1f44944292"
     cluster="m3ed.4b958d1f44944292"
     cluster_size="18 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="ramnit nimnul bmnup"
     md5_hashes="['b38d46aded8ccd3e4b37beaa2ee27983', 'b7a7d606ab5a076481f5a2ab9910c0ee', 'd90157f6fd918ae078c9c2ff5886f93c']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(156672,1536) == "0f4c07f5fc878e2aa1805fefc0c25f7a"
}

