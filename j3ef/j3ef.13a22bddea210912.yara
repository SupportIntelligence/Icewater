
rule j3ef_13a22bddea210912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3ef.13a22bddea210912"
     cluster="j3ef.13a22bddea210912"
     cluster_size="12"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="kranet malicious corrupt"
     md5_hashes="['0b7150ac2be179adf704c44821f1a5cc','28878659519b57512f57434aa1e8be54','fe8f90eb06e5cec4897e4eabd981a5f4']"

   strings:
      $hex_string = { 446973706c61794e616d65204c494b4520275441502d57696e25270000534f4654574152455c4d6963726f736f66745c57696e646f77735c43757272656e7456 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
