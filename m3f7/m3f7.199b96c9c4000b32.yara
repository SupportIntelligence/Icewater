
rule m3f7_199b96c9c4000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.199b96c9c4000b32"
     cluster="m3f7.199b96c9c4000b32"
     cluster_size="85"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker trojanclicker"
     md5_hashes="['040f2e8e6d04f42ee51c4ce319a10a32','082ceaa1063a5ad390e26836370f08af','4edd687936ac5f42fbbecf594013346e']"

   strings:
      $hex_string = { 6e74427949642827466f6c6c6f776572733127292c207b7d2c2027646973706c61794d6f646546756c6c2729293b0a5f5769646765744d616e616765722e5f52 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
