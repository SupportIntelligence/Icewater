import "hash"

rule m3e9_16d1baa94a9664f2
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.16d1baa94a9664f2"
     cluster="m3e9.16d1baa94a9664f2"
     cluster_size="1886 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="shipup razy zbot"
     md5_hashes="['3b4e562af20f3b2e0a676f6543ff6cc8', '2152e26c91adaafa87ac12e35856a5d8', '0d2867fe977061c44a97c055d1cb07c0']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(205298,1026) == "be5067a04c80e3830889c3baaa7d8293"
}

