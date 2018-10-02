
rule k2328_6ebb7949c8000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2328.6ebb7949c8000932"
     cluster="k2328.6ebb7949c8000932"
     cluster_size="84"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html iframeref"
     md5_hashes="['277f343f6253a63c78c39ee034c8a2fdaf3b2919','9b2ba04a6d30e796a22edabe8b4b908811da5f5e','fe3a620a261b987fbe0f32e253c58367ba524da4']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2328.6ebb7949c8000932"

   strings:
      $hex_string = { 703b69643d323026616d703b4974656d69643d34322220636c6173733d226d61696e6c6576656c22203e46656cfc6c65746be9707af520616e7961676f6b3c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
