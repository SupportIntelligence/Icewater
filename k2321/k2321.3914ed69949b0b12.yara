
rule k2321_3914ed69949b0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.3914ed69949b0b12"
     cluster="k2321.3914ed69949b0b12"
     cluster_size="8"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba emotet zusy"
     md5_hashes="['3e555ed4fdf901140c8f16bf3520e596','768cb9698a8f8174793d3e74bc00e6fd','e3281fd75dbd7b6ed97351a6109ca57e']"

   strings:
      $hex_string = { 9dafbd76fce85187dd66b1588e1d3d06e67df0fe7bed7c5ec962715928d9852456222c21448b454aa9c45fad421409f6d7614f8c30680d2ad26bb004ec417cca }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
