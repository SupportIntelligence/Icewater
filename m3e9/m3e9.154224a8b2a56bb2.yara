import "hash"

rule m3e9_154224a8b2a56bb2
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.154224a8b2a56bb2"
     cluster="m3e9.154224a8b2a56bb2"
     cluster_size="3 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="ramnit patched malicious"
     md5_hashes="['c04148b8566023677f073cf545baa0be', 'c04148b8566023677f073cf545baa0be', 'b76fb94d6950c8ee0fb3abaae9c68067']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(19968,1024) == "7759f3569cdbd6f76c76ae1144aaffe2"
}

