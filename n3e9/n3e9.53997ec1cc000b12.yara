
rule n3e9_53997ec1cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.53997ec1cc000b12"
     cluster="n3e9.53997ec1cc000b12"
     cluster_size="3046"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installerex antifw installrex"
     md5_hashes="['0013cfe585c068f0698dfd9bb1a2fd11','0020be2c0acbdc6fa291cf0e0ccb1741','0082df0633ea989acf49f8a5ea9ba4c8']"

   strings:
      $hex_string = { bf05d2692c9cbca2ca91cef9c9280b13f7f1636e99aee2a107237a762f776b6fcf9473726582b27b0d6cac4933bad60e9ad9530998e6d75f06c512296aa74eec }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
