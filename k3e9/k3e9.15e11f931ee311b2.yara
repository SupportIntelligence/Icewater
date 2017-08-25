import "hash"

rule k3e9_15e11f931ee311b2
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.15e11f931ee311b2"
     cluster="k3e9.15e11f931ee311b2"
     cluster_size="5 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['cb42e317f4714d4305c33fecfaf18492', 'cb42e317f4714d4305c33fecfaf18492', 'a52354d188a8d2f21abaac21c329d528']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(18432,1024) == "10e9282cad49722b603d799d81e34b3d"
}

