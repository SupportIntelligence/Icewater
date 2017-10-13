import "hash"

rule k3e9_6b66d34f0b4b5912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b66d34f0b4b5912"
     cluster="k3e9.6b66d34f0b4b5912"
     cluster_size="4 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob patched"
     md5_hashes="['2e7f59714b8c9a76f96c0c6302c48c75', 'c899e0ad042eb1153a6953a32067bb6b', 'cca8e1ae34428235431c5dbb68fe8855']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(14468,1036) == "3fc9b6513c182f90d41c33f933010485"
}

