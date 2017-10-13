import "hash"

rule m3e9_6a5ea44f2452d2d2
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.6a5ea44f2452d2d2"
     cluster="m3e9.6a5ea44f2452d2d2"
     cluster_size="7322 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['078ef4d7bd2a435912e08a522f0340a4', '03bb6f39bdce1b4ef948678927633343', '037545d95a89e7c3e599c81b5fc20c61']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(138240,1127) == "fddcc1b26534ac99f2294c97171db142"
}

