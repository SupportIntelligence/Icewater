
rule m3f7_699ce448c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.699ce448c0000b32"
     cluster="m3f7.699ce448c0000b32"
     cluster_size="10"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker clicker"
     md5_hashes="['077ef8c5a1d846e5e09f9fc1e7ed1857','0dc9d1a10f7f092d7dfb0090324bc437','f78837472a66e6344b3fb1665091643a']"

   strings:
      $hex_string = { 6e74427949642827466f6c6c6f776572733127292c207b7d2c2027646973706c61794d6f646546756c6c2729293b0a5f5769646765744d616e616765722e5f52 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
