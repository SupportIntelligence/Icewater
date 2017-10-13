import "hash"

rule m3e9_6a5ea44f2452d6d2
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.6a5ea44f2452d6d2"
     cluster="m3e9.6a5ea44f2452d6d2"
     cluster_size="351 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['10761da08b52e460a9e31df81509c6b2', '92663faa10e118d2da10098ddef25e37', 'b79e5ec8131dc8d2e990b45122b74d95']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(138240,1127) == "fddcc1b26534ac99f2294c97171db142"
}

