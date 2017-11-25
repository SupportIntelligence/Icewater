
rule n3e9_2b1fa448c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.2b1fa448c0000b32"
     cluster="n3e9.2b1fa448c0000b32"
     cluster_size="3"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dealply malicious btsgeneric"
     md5_hashes="['4c13095c2ff5d7a63126387466678783','5c9372beb9e3fdbc86a9a351ff40f482','b7135c13117f3c10cf7ba48441842499']"

   strings:
      $hex_string = { 79000000496d6167654c6973745f416464000000536176654443000056617269616e74436f70790000004765744443000000566572517565727956616c756541 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
