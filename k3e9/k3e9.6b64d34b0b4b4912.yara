import "hash"

rule k3e9_6b64d34b0b4b4912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64d34b0b4b4912"
     cluster="k3e9.6b64d34b0b4b4912"
     cluster_size="39 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="virut virtob patched"
     md5_hashes="['c8cf2a40f282650a6b1187e8345ce16a', '6027bf575171519b1f0c513c67c5e600', 'b1d0dd737bd23e90381ccab9c8b22657']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(18612,1036) == "6b61b0cff428f017f29ce22ade6c00dd"
}

