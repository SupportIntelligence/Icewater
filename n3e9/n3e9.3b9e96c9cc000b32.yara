
rule n3e9_3b9e96c9cc000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.3b9e96c9cc000b32"
     cluster="n3e9.3b9e96c9cc000b32"
     cluster_size="12"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="generickdz dealply malicious"
     md5_hashes="['0599f543016cc2aebc95ae618e32c2f2','08d8966fc9033f1029f7f6f9728c78b3','f348e82bda69bdd032ab056e54248fd5']"

   strings:
      $hex_string = { 004578697450726f63657373000000526567466c7573684b6579000000496d6167654c6973745f416464000000536176654443000056617269616e74436f7079 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
