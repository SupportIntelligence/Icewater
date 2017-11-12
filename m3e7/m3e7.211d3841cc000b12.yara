
rule m3e7_211d3841cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e7.211d3841cc000b12"
     cluster="m3e7.211d3841cc000b12"
     cluster_size="65"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="allaple rahack cryptor"
     md5_hashes="['2542a7406453bab244a5a4f35453bcd9','2acc6eccfa38ea854e39b92fe4edc807','b81401db614d6289c8ec115c8ab1a903']"

   strings:
      $hex_string = { d3eec8d43db62622e640a2aafdd6d97e5ff93ef41d0f52dd773efbac362abfb14f20f0430dc99156199f5df2d742c40e4e2eea063a00be72012d73aff71a68ad }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
