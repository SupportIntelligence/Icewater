import "hash"

rule k3e9_51b93336dda30932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.51b93336dda30932"
     cluster="k3e9.51b93336dda30932"
     cluster_size="73 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['1a21fe8855e61c564922a37dc3ef5d5e', '6c7abf774fe92a6e4e23066bb843ee5d', 'c2f556c649865a5008177e2b344ed507']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(20736,256) == "94ca2e8a517cf72614c288e379dbfbe9"
}

