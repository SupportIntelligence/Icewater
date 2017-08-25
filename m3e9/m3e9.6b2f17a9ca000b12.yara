import "hash"

rule m3e9_6b2f17a9ca000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.6b2f17a9ca000b12"
     cluster="m3e9.6b2f17a9ca000b12"
     cluster_size="11817 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['01e4b9377aca201a18d7f73ba7adf5f5', '01b852fe9636a814b10c40c9331d1873', '0b2ab6fb1a710d4927a3d29c2baef014']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(10240,1024) == "d6ce13b328d6c53dfb618f633f2323ac"
}

