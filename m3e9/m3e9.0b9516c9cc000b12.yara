
rule m3e9_0b9516c9cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.0b9516c9cc000b12"
     cluster="m3e9.0b9516c9cc000b12"
     cluster_size="7"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="qvod viking jadtre"
     md5_hashes="['2be61a479eca729cb99366ad3ff88b6c','3438ab28eea31d960fd22d2c7f273d38','fd90a9fde2d8c6d7032c4f8f2b49abc4']"

   strings:
      $hex_string = { 99121b9453a143bec5619e385c7f9caca0103ed581e6ae2caa1ce84aced25d298ced9552e2ba7dafdc5611fd28c107bf4d0d82ef02d86573976d3a6e912b671a }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
