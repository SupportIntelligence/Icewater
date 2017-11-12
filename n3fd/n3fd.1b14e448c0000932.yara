
rule n3fd_1b14e448c0000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3fd.1b14e448c0000932"
     cluster="n3fd.1b14e448c0000932"
     cluster_size="19"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="zusy malicious attribute"
     md5_hashes="['0bf08407ab6e90d066026d0c3635f72f','14647512ff29cf7406e730d4bc321da4','a7320f32d940b8bb718c0c3a6c2d6362']"

   strings:
      $hex_string = { 517531fb657011fe29f810ffd27ffdab7e15f216cca9bff2b7c3c4ffab8f7fb7ff7ab96393786f89059edef997ee1f64bfefaf4f7d59fefaafff0ba8903ff81f }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
