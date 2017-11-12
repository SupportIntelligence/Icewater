import "hash"

rule k3e9_51b9312695a31132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.51b9312695a31132"
     cluster="k3e9.51b9312695a31132"
     cluster_size="9"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171105"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['1fdf5c0a6d68bf5cdd5984cc970b1b52','b5f1ab591f676aa86093d451c85e89a5','e78b9dd425cab536b62fae7bb97c68a9']"


   condition:
      
      filesize > 16384 and filesize < 65536
      and hash.md5(20480,4096) == "be1070b2c2c331a2fbb604474784a677"
}

