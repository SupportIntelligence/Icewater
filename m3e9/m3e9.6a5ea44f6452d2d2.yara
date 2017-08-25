import "hash"

rule m3e9_6a5ea44f6452d2d2
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.6a5ea44f6452d2d2"
     cluster="m3e9.6a5ea44f6452d2d2"
     cluster_size="638 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['a32d67cb9debeb873c5c55486e3f9b2b', 'a874e2e8fc083e09bfcdcc7f5c053ec7', 'aca4a12a49b98d22763aa493bb262609']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(138240,1127) == "fddcc1b26534ac99f2294c97171db142"
}

