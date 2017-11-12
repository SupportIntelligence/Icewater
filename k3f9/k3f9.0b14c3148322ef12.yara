
rule k3f9_0b14c3148322ef12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f9.0b14c3148322ef12"
     cluster="k3f9.0b14c3148322ef12"
     cluster_size="1771"
     filetype = "MS-DOS executable"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vabushky malicious alureon"
     md5_hashes="['000f2a4f07b77e2ce7cc6cf3012f81dd','00fd25eccce51fd99e1eda12a5880205','02e967493229e4acf5ddb95bd02b0427']"

   strings:
      $hex_string = { be0fb8ac9a37a2492bd831fa1bd30055e47329fa56f363bb322cbbfaf7b0b094e5c1bcf999b35e6e198ee85e25fe16e99ecd49661ed2b9bee83e2360279461d3 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
