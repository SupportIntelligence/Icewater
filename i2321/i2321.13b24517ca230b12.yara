
rule i2321_13b24517ca230b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i2321.13b24517ca230b12"
     cluster="i2321.13b24517ca230b12"
     cluster_size="5"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="padodor backdoor symmi"
     md5_hashes="['6065bb6bf03337a6ceaefdfb885bf701','98227e9655238de475acb2e876e6d623','e1db2e9b12c77f1ebb700dd61dcac4d8']"

   strings:
      $hex_string = { ea7019160ef1980efbf97417aeb0b81947897dedf60a49b62f6e9263bcbd28aa520a48573aa85e7f6f28fdb73e87e3e0a21c4a38dff7a13635f44f75f8081812 }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
