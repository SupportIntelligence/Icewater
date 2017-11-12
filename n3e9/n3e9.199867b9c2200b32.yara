
rule n3e9_199867b9c2200b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.199867b9c2200b32"
     cluster="n3e9.199867b9c2200b32"
     cluster_size="8"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ransom zusy cerber"
     md5_hashes="['4f8f550ed59d75a900a76484a5da2edd','5cc59452a556c6300927f7b12c0eac43','f4869b3506fa61dbdd32e25b04423c5a']"

   strings:
      $hex_string = { 7a26837c177ba22389df808da348370535d5763adab43ccbd3c9c494860218f49b13ddd43f844fa6eedc5bbc0b4dd1d89b9db7aef5bfc6b201ebad989c065366 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
