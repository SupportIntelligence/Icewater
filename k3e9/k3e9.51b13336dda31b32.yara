import "hash"

rule k3e9_51b13336dda31b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.51b13336dda31b32"
     cluster="k3e9.51b13336dda31b32"
     cluster_size="707 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['b4263cb2dee5ad27735ffae313466062', 'a350862b4eb41f60b77617e8a845c957', 'b708f2f9855b4ecaf034ca229af617a4']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(21504,1024) == "ed02a3681ee34c27a22bf7a4a139d018"
}

