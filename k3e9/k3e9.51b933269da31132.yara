import "hash"

rule k3e9_51b933269da31132
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.51b933269da31132"
     cluster="k3e9.51b933269da31132"
     cluster_size="208 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['8e13f473e4c7e603f510afb6c054b26f', 'baea46cb844e1b050c4ca6751108a144', '0a51334a02647d4ab54bac903865fc92']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(5120,1024) == "5ab8258470efa3d600fcbe17d59a8cd4"
}

