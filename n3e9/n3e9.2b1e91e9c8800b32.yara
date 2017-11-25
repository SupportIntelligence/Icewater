
rule n3e9_2b1e91e9c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.2b1e91e9c8800b32"
     cluster="n3e9.2b1e91e9c8800b32"
     cluster_size="22"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dealply malicious attribute"
     md5_hashes="['1214769330f3a8362cc02a54748128ee','13ed78be603e6eaf80eb175ea8adf63c','cfcabb2ab317edde9b27ebf20732f374']"

   strings:
      $hex_string = { 004578697450726f63657373000000526567466c7573684b6579000000496d6167654c6973745f416464000000536176654443000056617269616e74436f7079 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
