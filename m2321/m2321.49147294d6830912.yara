
rule m2321_49147294d6830912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.49147294d6830912"
     cluster="m2321.49147294d6830912"
     cluster_size="84"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="elemental elementa jtvn"
     md5_hashes="['01cca5e007a02e2071ecb4c226081e6e','022dbbdf49cdccb0ec10915779a4740c','22e44754ac2d96f5dad73db482805f17']"

   strings:
      $hex_string = { 34d70a95d800316eda7263cd493ed0f0e6c9391e4d61d483b5c6b8b98e239b3b20b746bc16547143d5fdd3360ef7681ab9a8e4aae9317c771f5775df5d428037 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
