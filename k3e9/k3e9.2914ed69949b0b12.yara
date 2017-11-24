
rule k3e9_2914ed69949b0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.2914ed69949b0b12"
     cluster="k3e9.2914ed69949b0b12"
     cluster_size="32"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba zusy vbkrypt"
     md5_hashes="['0bd3d2b459ef882aee71c133f0f04958','16ce7c82274b9f8e76c95529dea4e927','6101ca42a5c649298dd80c9ad0eaf004']"

   strings:
      $hex_string = { 9dafbd76fce85187dd66b1588e1d3d06e67df0fe7bed7c5ec962715928d9852456222c21448b454aa9c45fad421409f6d7614f8c30680d2ad26bb004ec417cca }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
