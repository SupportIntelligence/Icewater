
rule n3e9_291c7b49c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.291c7b49c8000b12"
     cluster="n3e9.291c7b49c8000b12"
     cluster_size="55"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="symmi dealply malicious"
     md5_hashes="['00630fd00a573a4af6620baa82186a38','01717a9fd5fc17e79eaab3ca3c427cc4','297f9d13180bbf48af06657bc2656a43']"

   strings:
      $hex_string = { 004578697450726f63657373000000526567436c6f73654b6579000000496d6167654c6973745f41646400000053617665444300004973457175616c47554944 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
