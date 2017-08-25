import "hash"

rule m3e9_1918bb29c8800912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.1918bb29c8800912"
     cluster="m3e9.1918bb29c8800912"
     cluster_size="3653 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="browsefox riskware adplugin"
     md5_hashes="['115b125131395ab786b843918fe0fa2a', '022711deb1cf1c8f98585aba6e86c05b', '018ae68ba04ec6855f415f6ee9d155e9']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(96768,1024) == "1fbda6246048c36f833f0380b13011b2"
}

