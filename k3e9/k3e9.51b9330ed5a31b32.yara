import "hash"

rule k3e9_51b9330ed5a31b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.51b9330ed5a31b32"
     cluster="k3e9.51b9330ed5a31b32"
     cluster_size="11 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['a4d8e1f3840f583695be383c447352e3', 'db31cd1e10251dd0f8928c6116018226', 'bdbba73a857bc4a366b2aa24661c9ed5']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(20736,256) == "94ca2e8a517cf72614c288e379dbfbe9"
}

