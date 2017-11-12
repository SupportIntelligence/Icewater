
rule n3e9_214dadbcc1010b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.214dadbcc1010b12"
     cluster="n3e9.214dadbcc1010b12"
     cluster_size="782"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['02083815920d39e84a2038f8791979f5','02fc941f08331d6462a99d3429ff621a','0e203d17399dfba6ae720f98e89dc2c7']"

   strings:
      $hex_string = { 0f2f0b0b0f2f0f2f0f2f0f0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b00000b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0a }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
