
rule n3f1_4b16848bc6220b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f1.4b16848bc6220b32"
     cluster="n3f1.4b16848bc6220b32"
     cluster_size="5"
     filetype = "application/zip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="hiddenads androidos andr"
     md5_hashes="['4da47c5d3762cd4296deb4ca469d5b6d','cb598bbd486d7c8f140c2b1e7cf9ae10','ff5fa5360a1e4175600649bac9227bfe']"

   strings:
      $hex_string = { bd4c2b663ac3a3b3040b0ca4a7e450d65ae0b6d3743495c798b783e64d24d27ea04028f8bb70e2962df0d7e5cdfb805633309caf5ca13fab037389ec4825913c }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
