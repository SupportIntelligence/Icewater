import "hash"

rule k3e9_16c31d971ee30094
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.16c31d971ee30094"
     cluster="k3e9.16c31d971ee30094"
     cluster_size="4"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171105"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob malicious"
     md5_hashes="['4f4e434bc8a09a8254e8ac5eb1e9c191','b7147a9d781319d8147d5988bf9899a0','dcc330f0d22f0db2f0331c4c0e8b6c95']"


   condition:
      
      filesize > 16384 and filesize < 65536
      and hash.md5(16384,4096) == "6bad58c61253cbc792854ba28636beeb"
}

