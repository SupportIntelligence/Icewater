import "hash"

rule k3e9_073c3f59526b491e
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.073c3f59526b491e"
     cluster="k3e9.073c3f59526b491e"
     cluster_size="7475"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171105"
     license = "RIL-1.0 [Rick's Internet License] "
     family="servstart nitol cfecc"
     md5_hashes="['0002b0334a0a336ad5eec83184bc28de','003a63abbe7e8e4944c855602fa1719a','017bb7ac55ad75f0e1ffa81faca8dc27']"


   condition:
      
      filesize > 65536 and filesize < 262144
      and hash.md5(16384,16384) == "45ccf91d575e168af4da1a887a475b27"
}

