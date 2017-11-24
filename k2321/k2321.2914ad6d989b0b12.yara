
rule k2321_2914ad6d989b0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.2914ad6d989b0b12"
     cluster="k2321.2914ad6d989b0b12"
     cluster_size="14"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba emotet zusy"
     md5_hashes="['087643a6e07cc94edf0c1c3f074df942','0b22bcdabbcfa4cc54adc99e5cca880e','f48b590a292b2cf63071a09ab2dc8e4d']"

   strings:
      $hex_string = { 9e7ceda597f3b2b3fbf7ea151614a8954a41948860006304ba90198a5d743af03f313a6ac88001a573e6bcffeebb674e9fbefeebaf2e3c7e7bfae4e9a387bfd1 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
