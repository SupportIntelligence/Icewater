
rule k3e9_2a59a12c8ac2d131
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.2a59a12c8ac2d131"
     cluster="k3e9.2a59a12c8ac2d131"
     cluster_size="3470"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dropped malicious zbot"
     md5_hashes="['007c4c33b7b4502bc2ace6794c9f31bd','0120c6c21604e3052e2769b812a1ff75','052454616aa685d7204be3eb3bbd87a9']"

   strings:
      $hex_string = { 14c1e01023da578b7c241c0bc36689710289790889410483c10c8321003bf27f1585f67e1523c20fafc6575051e83ae7ffff85c0750433c0eb0333c0405f5e5b }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}
