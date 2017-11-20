
rule m2321_416e035aa2196b96
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.416e035aa2196b96"
     cluster="m2321.416e035aa2196b96"
     cluster_size="58"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family=""
     md5_hashes="['02925622285c9b71940e7e7e9dc81a7a','17badefd68bb1f8639a403a1f78dcaae','5ad5129075218efc3b974a5260c07b3d']"

   strings:
      $hex_string = { 4feb4994f7477edd83fd3438c65d54abf4aff551a08a65230a9e42b930e85041d5b726a8951d328c5619d38e00914cdc1311e39d661a0b88bcd6cd396aa6beaa }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
