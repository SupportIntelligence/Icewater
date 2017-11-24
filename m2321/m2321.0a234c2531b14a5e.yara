
rule m2321_0a234c2531b14a5e
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.0a234c2531b14a5e"
     cluster="m2321.0a234c2531b14a5e"
     cluster_size="8"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="viking jadtre nimnul"
     md5_hashes="['231dfcf38f4c13920071d7232b6e38fa','636bc6ee2754fd6be8173d5bea04c6fe','f7f0dea8dc658755c6a30c93368b3e03']"

   strings:
      $hex_string = { d4eb2865821c2c4bde39a5b9533b4c8b501381fc758cc75c88f4cd588fdd40295ea47ae0229ee998aecec8f321c1bf99bea1dc93d6c3f8a9e379b54f92123dda }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
