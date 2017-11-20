
rule m3e9_693f85a4d7a31912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.693f85a4d7a31912"
     cluster="m3e9.693f85a4d7a31912"
     cluster_size="92"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="qvod viking jadtre"
     md5_hashes="['050a4d029a9c529b5382eaa259f16658','068f7d3950da71916c6faa035fa6426b','a3ab0ff9c1032cdb021372a90d19d0d0']"

   strings:
      $hex_string = { 19f9a177f599b2f22e695ccac110fb3e7b41fd1deebc1b8272ef24255acfac07b4dc5dcdc9a28cfff673985374c44b653100d428188bbd12435608b5142f13e0 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
