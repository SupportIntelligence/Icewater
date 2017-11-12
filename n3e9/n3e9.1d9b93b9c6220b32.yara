
rule n3e9_1d9b93b9c6220b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.1d9b93b9c6220b32"
     cluster="n3e9.1d9b93b9c6220b32"
     cluster_size="32"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="zusy malicious ransom"
     md5_hashes="['0018f259d3f67d240f4de9c7858d69ef','0a25be35b4a676892a8bcf3b4ce89fd9','9195e32af469d7f7d8a199cf3304d9e2']"

   strings:
      $hex_string = { 3603259887392832c8e5347a40c046d2f81d5ee105baf0c9505f02726c3e0b15588245283330cb09f5008f4da461079ee011daf0c690810414785b69be7c7152 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
