
rule o2321_3a4941424a415456
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o2321.3a4941424a415456"
     cluster="o2321.3a4941424a415456"
     cluster_size="9"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family=""
     md5_hashes="['16efa98bd34effaa731abad5be632219','1b63e0a84f71f96f2b2625775ad3ec38','fc51927224713ea2dfe843cd7b67498d']"

   strings:
      $hex_string = { 727162edab46cd04eb6ea8508e584a2967b536917d166aa4e189a95615117e9205a5230920e385c9fa3c52aa012e34733e4cccfd9a9f35d11b2407b82dd790d8 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
