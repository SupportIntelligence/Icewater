
rule n2319_6b2cb6c9c8000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.6b2cb6c9c8000912"
     cluster="n2319.6b2cb6c9c8000912"
     cluster_size="13"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="faceliker script autolike"
     md5_hashes="['83b27373b42f5a101cdb76b056823b9e4e3000bf','3a863638e38e4183b7c886fad6bdd2ecd524bd19','f0ae85e4ba851bb20fe78e069666a37e74be7588']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.6b2cb6c9c8000912"

   strings:
      $hex_string = { 43454445383b207d0a237265706c792d7469746c65207b206261636b67726f756e643a75726c28687474703a2f2f696d673239312e696d616765736861636b2e }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
