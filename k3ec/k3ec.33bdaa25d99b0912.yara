
rule k3ec_33bdaa25d99b0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3ec.33bdaa25d99b0912"
     cluster="k3ec.33bdaa25d99b0912"
     cluster_size="9"
     filetype = "PE32 executable (console) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="antavmu fileinfector moctezuma"
     md5_hashes="['2ce5b9e831a5da1ecd6dd9c90c9e8e02','3776ffc475fddee6153dcd780c88c2d4','f43f2481fd8688755d80ce67c86bbb77']"

   strings:
      $hex_string = { 8385bf4400744d363941cc35c0def57162c1c23a2814be4ffc98c77b8c077b3cc9e63b025cd1ef75edff27321dcdd494e9aeff49a6f7ec31f25548e419fa6d23 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
