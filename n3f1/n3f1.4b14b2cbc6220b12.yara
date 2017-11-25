
rule n3f1_4b14b2cbc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f1.4b14b2cbc6220b12"
     cluster="n3f1.4b14b2cbc6220b12"
     cluster_size="15"
     filetype = "application/zip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="hiddenads androidos andr"
     md5_hashes="['2f8fb461bce617e720ba59f210acfe63','3b372f908a3f46313e2400dacbd2debe','ea6fe2a1338680862c2f1bef6813adee']"

   strings:
      $hex_string = { bd4c2b663ac3a3b3040b0ca4a7e450d65ae0b6d3743495c798b783e64d24d27ea04028f8bb70e2962df0d7e5cdfb805633309caf5ca13fab037389ec4825913c }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
