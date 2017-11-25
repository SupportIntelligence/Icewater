
rule m3e9_136e7ec1c8001116
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.136e7ec1c8001116"
     cluster="m3e9.136e7ec1c8001116"
     cluster_size="433"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installcore unwanted riskware"
     md5_hashes="['00c4dad1de3ed8ee1aa85254e65dbadd','00d08e2ab44a73d477b90deff1177770','0dd61c06fb3aaaca4a804fdc1cd9c970']"

   strings:
      $hex_string = { 5077a4a0ce510355ff0ed768a617556e29c4b4ceeaa176a94f001d13327feff98eae8c39bf2bef6959591b11139e23c69bc71921bc22e80cdf72f14b9973e4d5 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
