
rule n3e9_2b1c1cc9cc000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.2b1c1cc9cc000b32"
     cluster="n3e9.2b1c1cc9cc000b32"
     cluster_size="12"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dealply malicious filerepmalware"
     md5_hashes="['01441217ed9479cb82f9017a440bef98','4d1a791d87a0babceeac2b119b1acc2d','f09f5abaca92689ef2db31d847c512c6']"

   strings:
      $hex_string = { 4578697450726f63657373000000526567466c7573684b6579000000496d6167654c6973745f416464000000536176654443000056617269616e74436f707900 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
